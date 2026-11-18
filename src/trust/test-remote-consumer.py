#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import copy
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time


LIMIT = 1024 * 1024
TIMEOUT = 5
HOST = "consumer.test"
PHASE = "enter-initrd:leave-initrd:sysinit:ready"
PCR11 = "bbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9da"
EK = ("007a0023000b000300b20020837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa"
      "00060080004300100003001000206b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
      "00204fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
CHECKS = ("expectedKeyMatched", "nonceMatched", "quoteSignatureVerified", "nvSignatureVerified",
          "pcrDigestVerified", "nvPublicVerified", "runtimeReplayVerified", "approvedPcr11Matched",
          "authenticationDeclarationMatched", "activeEnrollmentMatched", "singleUseChallengeConsumed")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def encoded(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate field")
        result[key] = value
    return result


def invalid_constant(_value):
    raise ValueError("Invalid JSON constant")


def parsed(data):
    return json.loads(data, object_pairs_hook=object_pairs, parse_constant=invalid_constant)


def write(path, data):
    with open(path, "xb") as stream:
        stream.write(data)


def run(arguments, reject=False):
    result = subprocess.run([str(value) for value in arguments], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=TIMEOUT, check=False)
    require(len(result.stdout) <= LIMIT and len(result.stderr) <= LIMIT, "Excessive command output")
    require(b"Sanitizer" not in result.stderr and b"runtime error:" not in result.stderr,
            "Instrumented command failed")
    require(result.returncode == (1 if reject else 0), "Unexpected command status")
    if reject:
        require(not result.stdout, "Rejected command printed a result")
    elif Path(arguments[0]).name != "openssl":
        require(not result.stderr, "Successful command printed diagnostics")
    return result.stdout


def clock():
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def receive_exact(connection, size, deadline):
    value = bytearray()
    while len(value) < size:
        remaining = deadline - clock()
        if remaining <= 0:
            raise TimeoutError("Frame deadline expired")
        connection.settimeout(remaining)
        chunk = connection.recv(size - len(value))
        if not chunk:
            raise EOFError("Incomplete frame")
        value.extend(chunk)
    return bytes(value)


def receive(connection, limit=LIMIT):
    deadline = clock() + TIMEOUT
    size = struct.unpack("!I", receive_exact(connection, 4, deadline))[0]
    if size == 0 or size > limit:
        raise ValueError("Invalid frame size")
    return parsed(receive_exact(connection, size, deadline))


def send(connection, value):
    data = encoded(value)
    require(0 < len(data) <= LIMIT, "Invalid outgoing frame size")
    connection.settimeout(TIMEOUT)
    connection.sendall(struct.pack("!I", len(data)) + data)


def fields(value, expected):
    return isinstance(value, dict) and value.keys() == set(expected)


def certificates(directory):
    result = {}
    for name in ("ca", "foreign-ca"):
        key, certificate = directory / (name + ".key"), directory / (name + ".pem")
        run(["openssl", "req", "-new", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
             "-nodes", "-keyout", key, "-out", certificate, "-days", "1", "-subj", "/CN=" + name,
             "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
        result[name] = (str(certificate), str(key))
    for serial, name in enumerate(("server", "account-a", "account-b", "unmapped", "foreign", "wrong-purpose"), 1):
        key, request, certificate = (directory / (name + suffix) for suffix in (".key", ".csr", ".pem"))
        extensions = directory / (name + ".extensions")
        purpose = "serverAuth" if name in ("server", "wrong-purpose") else "clientAuth"
        text = "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=" + purpose + "\n"
        if name == "server":
            text += "subjectAltName=DNS:" + HOST + "\n"
        write(extensions, text.encode())
        run(["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
             "-keyout", key, "-out", request, "-subj", "/CN=" + name])
        ca, ca_key = result["foreign-ca" if name == "foreign" else "ca"]
        run(["openssl", "x509", "-req", "-in", request, "-CA", ca, "-CAkey", ca_key, "-set_serial", str(serial),
             "-days", "1", "-extfile", extensions, "-out", certificate])
        result[name] = (str(certificate), str(key))
    return result


def fingerprint(certificate):
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(Path(certificate).read_text())).hexdigest()


def context(certificates, server=False, client="account-a", authority="ca"):
    result = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    result.minimum_version = ssl.TLSVersion.TLSv1_3
    result.verify_mode = ssl.CERT_REQUIRED
    result.load_verify_locations(cafile=certificates[authority][0])
    if server or client is not None:
        result.load_cert_chain(*certificates["server" if server else client])
    return result


def connect(port, certificates, client="account-a", authority="ca", hostname=HOST):
    raw = socket.create_connection(("127.0.0.1", port), timeout=TIMEOUT)
    try:
        return context(certificates, client=client, authority=authority).wrap_socket(raw, server_hostname=hostname)
    except BaseException:
        raw.close()
        raise


def fixture_record(ak):
    public = bytes.fromhex(ak)
    key_id = hashlib.sha256(public).hexdigest()
    # Active records are software fixtures, not credential-activation evidence.
    return {"format": "io.platformd.Trust.Enrollment.v1", "keyId": key_id, "ekPublicHex": EK,
            "akPublicHex": ak, "akNameHex": "000b" + hashlib.sha256(public[2:]).hexdigest(),
            "state": "active", "generation": 1, "enrolledRealtimeUSec": 1, "revokedRealtimeUSec": 0,
            "pending": None, "request": None}


def serve(control, configuration):
    os.setsid()
    grants = []
    issued = []
    completed = []
    denied = 0
    handshakes = 0
    directory = Path(configuration["directory"])
    command = configuration["command"]
    state = "--state-dir=" + str(directory / "state")
    try:
        tls = context(configuration["certificates"], server=True)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(2)
            listener.settimeout(TIMEOUT)
            control.send({"port": listener.getsockname()[1]})
            for connection_index in range(configuration["connections"]):
                raw, _address = listener.accept()
                raw.settimeout(TIMEOUT)
                try:
                    with tls.wrap_socket(raw, server_side=True) as connection:
                        handshakes += 1
                        principal = configuration["principals"].get(hashlib.sha256(connection.getpeercert(binary_form=True)).hexdigest())
                        if principal is None:
                            raise ValueError("Unknown principal")
                        start = receive(connection, 4096)
                        if not fields(start, ("begin",)) or start["begin"] is not True:
                            raise ValueError("Invalid request")
                        key_id = principal["key"]
                        lifetime = configuration["lifetime"]
                        deadline = clock() + lifetime
                        request_file = directory / ("request-" + str(connection_index) + ".json")
                        policy = {"uid": principal["uid"], "sessionId": principal["session"], "audience": principal["audience"],
                                  "operationDigestHex": hashlib.sha256(principal["operation"].encode()).hexdigest()}
                        write(request_file, encoded(policy))
                        challenge = parsed(run([command, "request-begin", key_id, state, "--request=" + str(request_file),
                                                "--lifetime=" + str(lifetime)]))
                        require(challenge.get("format") == "io.platformd.Trust.AuthenticationRequest.v1" and
                                challenge.get("keyId") == key_id, "Invalid request output")
                        expected = {"uid": policy["uid"], "sessionId": policy["sessionId"],
                                    "context": {"challengeHex": challenge["requestId"], "audience": policy["audience"],
                                                "operationDigestHex": policy["operationDigestHex"]}}
                        require(challenge.get("request") == expected, "Request policy changed")
                        issued.append({"account": principal["account"], "id": challenge["requestId"]})
                        send(connection, challenge)
                        if configuration["revoke"]:
                            revoked = parsed(run([command, "enrollment-revoke", key_id, state]))
                            require(revoked.get("state") == "revoked", "Enrollment revocation failed")
                        response = receive(connection)
                        if not fields(response, ("token",)) or not isinstance(response["token"], dict):
                            raise ValueError("Invalid response")
                        token_file = directory / ("token-" + str(connection_index) + ".json")
                        write(token_file, encoded(response["token"]))
                        arguments = [command, "request-complete", key_id, state, "--request-id=" + challenge["requestId"],
                                     "--token=" + str(token_file), "--reference=" + principal["reference"], "--phase=" + PHASE,
                                     "--allow-root-declared-authentication"]
                        if configuration["appraisal_rejected"]:
                            run(arguments, reject=True)
                            completed.append(False)
                            raise ValueError("Appraisal rejected")
                        report = parsed(run(arguments))
                        require(report.get("profile") == "io.platformd.Trust.RequestAppraisal.v1" and
                                report.get("authenticationQuality") == "root-declared" and report.get("keyId") == key_id and
                                report.get("request") == expected and report.get("approvedPhase") == PHASE and
                                all(report.get(name) is True for name in CHECKS), "Incomplete appraisal")
                        completed.append(True)
                        if configuration["delay_grant"]:
                            time.sleep(max(0, deadline - clock()) + 0.02)
                        if clock() >= deadline:
                            raise ValueError("Operation expired")
                        grants.append({"account": principal["account"], "operation": principal["operation"]})
                        send(connection, {"granted": True})
                        if configuration["replay"]:
                            repeated = receive(connection)
                            require(repeated == response, "Replay fixture changed")
                            run(arguments, reject=True)
                            raise ValueError("Operation consumed")
                except (OSError, ValueError, EOFError, RecursionError):
                    denied += 1
                finally:
                    raw.close()
        records = {name: parsed(path.read_bytes()) for name, path in
                   ((path.stem, path) for path in (directory / "state").glob("*.json"))}
        control.send({"grants": grants, "issued": issued, "completed": completed, "denied": denied,
                      "handshakes": handshakes, "records": records})
    except BaseException as error:
        control.send({"error": str(error) if isinstance(error, AssertionError) else type(error).__name__})
    finally:
        control.close()


def token(fixture, directory, key, request, mutation=None):
    value = copy.deepcopy(request)
    if mutation == "uid":
        value["uid"] += 1
    elif mutation == "session":
        value["sessionId"] += "-other"
    elif mutation == "audience":
        value["context"]["audience"] += "/other"
    elif mutation == "operation":
        value["context"]["operationDigestHex"] = "b" * 64
    elif mutation == "challenge":
        value["context"]["challengeHex"] = "b" * 64
    request_file = directory / "request.json"
    write(request_file, encoded(value))
    run([fixture, "--write-request-fixture", directory, key, request_file])
    return parsed((directory / "token.json").read_bytes())


def exercise(case, directory, command, fixture, certificates, keys):
    verifier = directory / "verifier"
    attester = directory / "attester"
    verifier.mkdir(mode=0o700)
    attester.mkdir(mode=0o700)
    (verifier / "state").mkdir(mode=0o700)
    principals = {}
    records = {}
    for name in ("account-a", "account-b"):
        record = fixture_record((keys[name] / "ak.hex").read_text().strip())
        records[name] = record
        write(verifier / "state" / (record["keyId"] + ".json"), encoded(record))
        reference = verifier / (name + "-reference.json")
        write(reference, encoded({"sha256": [{"phase": PHASE, "pcr": 11,
                                              "hash": "0" * 64 if case == "reference" else PCR11}]}))
        principals[fingerprint(certificates[name][0])] = {
            "account": name, "key": record["keyId"], "uid": 1000 if name == "account-a" else 1001,
            "session": "fixture-session", "reference": str(reference), "audience": "https://" + HOST,
            "operation": name + "\x00read\x00fixture-resource\x00operation-1"}
    configuration = {"command": command, "directory": str(verifier), "certificates": certificates,
                     "principals": principals, "connections": 2 if case in ("cross-account", "reconnect") else 1,
                     "lifetime": 1 if case in ("expiry", "grant-expiry") else 30,
                     "revoke": case == "revoked", "delay_grant": case == "grant-expiry", "replay": case == "replay",
                     "appraisal_rejected": case in ("uid", "session", "audience", "operation", "challenge", "key",
                                                    "reference", "expiry", "revoked", "cross-account")}
    local, remote = multiprocessing.get_context("spawn").Pipe()
    process = multiprocessing.get_context("spawn").Process(target=serve, args=(remote, configuration))
    process.start()
    remote.close()
    result = None
    try:
        require(local.poll(TIMEOUT), "Verifier did not start")
        ready = local.recv()
        require("port" in ready, "Verifier failed to start: " + ready.get("error", ""))
        port = ready["port"]
        client = {"missing-client": None, "untrusted-client": "foreign", "unmapped-client": "unmapped",
                  "wrong-purpose": "wrong-purpose", "positive-b": "account-b"}.get(case, "account-a")
        authority = "foreign-ca" if case == "server-ca" else "ca"
        hostname = "other.test" if case == "server-name" else HOST
        network_failed = False
        server_identity_failed = False
        try:
            with connect(port, certificates, client, authority, hostname) as connection:
                if case == "malformed":
                    connection.sendall(struct.pack("!I", 1) + b"{")
                elif case == "duplicate":
                    data = b'{"begin":true,"begin":true}'
                    connection.sendall(struct.pack("!I", len(data)) + data)
                elif case == "oversized":
                    connection.sendall(struct.pack("!I", LIMIT + 1))
                elif case in ("truncated", "stalled"):
                    connection.sendall(struct.pack("!I", 20) + b"{")
                elif case == "disconnect":
                    pass
                elif case == "request-injection":
                    send(connection, {"begin": True, "account": "account-b", "key": records["account-b"]["keyId"]})
                else:
                    send(connection, {"begin": True})
                    challenge = receive(connection)
                    signing_key = keys["account-b" if case in ("key", "positive-b") else "account-a"] / "key.pem"
                    value = token(fixture, attester, signing_key, challenge["request"], case)
                    response = {"token": value}
                    if case == "response-injection":
                        response["reference"] = "attester-reference.json"
                    if case in ("cross-account", "reconnect"):
                        connection.close()
                        with connect(port, certificates, "account-b" if case == "cross-account" else "account-a") as second:
                            if case == "cross-account":
                                send(second, {"begin": True})
                                other = receive(second)
                                require(other["keyId"] == records["account-b"]["keyId"] and
                                        other["requestId"] != challenge["requestId"], "Other account request not issued")
                            send(second, response)
                            receive(second)
                    else:
                        if case == "expiry":
                            time.sleep(1.05)
                        send(connection, response)
                        reply = receive(connection)
                        require(reply == {"granted": True} and case in ("positive", "positive-b", "replay"), "Unexpected operation grant")
                        if case == "replay":
                            send(connection, response)
                            receive(connection)
                if case not in ("positive", "positive-b", "replay", "cross-account", "reconnect", "disconnect", "truncated"):
                    receive(connection)
        except ssl.SSLCertVerificationError:
            network_failed = True
            server_identity_failed = True
        except (OSError, EOFError):
            network_failed = True
        require(case not in ("positive", "positive-b") or not network_failed, "Positive connection failed")
        require(server_identity_failed == (case in ("server-ca", "server-name")), "Unexpected server identity result")
        require(local.poll(TIMEOUT + 1), "Verifier did not finish")
        result = local.recv()
        require("error" not in result, "Verifier failed: " + result.get("error", ""))
        process.join(TIMEOUT)
        require(not process.is_alive() and process.exitcode == 0, "Verifier did not exit cleanly")
    finally:
        if process.is_alive():
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                process.terminate()
            process.join(TIMEOUT)
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.join(TIMEOUT)
        local.close()
        process.close()
    account = "account-b" if case == "positive-b" else "account-a"
    expected_grants = [{"account": account, "operation": principals[fingerprint(certificates[account][0])]["operation"]}] \
        if case in ("positive", "positive-b", "replay") else []
    require(result["grants"] == expected_grants, "Incorrect operation grants")
    require(result["denied"] == (0 if case in ("positive", "positive-b") else configuration["connections"]), "Incorrect rejection count")
    require(result["handshakes"] == (0 if case in ("missing-client", "untrusted-client", "wrong-purpose", "server-ca", "server-name")
                                     else configuration["connections"]), "Incorrect TLS handshake count")
    if case in ("positive", "positive-b", "replay", "grant-expiry"):
        require(result["completed"] == [True], "Positive appraisal not performed")
    elif configuration["appraisal_rejected"]:
        require(result["completed"] == [False], "Negative appraisal not performed")
    else:
        require(not result["completed"], "Unexpected appraisal")
    if result["issued"]:
        expected_accounts = ["account-a", "account-b"] if case == "cross-account" else [account]
        require([value["account"] for value in result["issued"]] == expected_accounts, "Incorrect request account")
        stored = result["records"][records[account]["keyId"]]
        if case in ("cross-account", "reconnect", "response-injection"):
            require(stored["request"]["requestId"] == result["issued"][0]["id"] and stored["generation"] == 2,
                    "Rejected connection changed pending request")
        else:
            require(stored["request"] is None, "Completed request retained")
        require(stored["state"] == ("revoked" if case == "revoked" else "active"), "Unexpected enrollment state")
    else:
        require(result["records"][records["account-a"]["keyId"]] == records["account-a"], "Rejected peer changed enrollment")
    if case == "cross-account":
        other = result["records"][records["account-b"]["keyId"]]
        require(other["request"] is None and other["generation"] == 3 and other["state"] == "active",
                "Other account completion not consumed")
    else:
        untouched = "account-a" if case == "positive-b" else "account-b"
        require(result["records"][records[untouched]["keyId"]] == records[untouched], "Other account changed")


def main():
    require(len(sys.argv) == 3, "Expected trustctl and fixture generator")
    command, fixture = (str(Path(argument).resolve()) for argument in sys.argv[1:])
    os.umask(0o077)
    cases = ("positive", "positive-b", "missing-client", "untrusted-client", "unmapped-client", "wrong-purpose", "server-ca", "server-name",
             "cross-account", "reconnect", "uid", "session", "audience", "operation", "challenge", "key", "reference",
             "request-injection", "response-injection", "replay", "expiry", "grant-expiry", "revoked", "malformed",
             "duplicate", "oversized", "truncated", "stalled", "disconnect")
    with tempfile.TemporaryDirectory(prefix="platformd-remote-consumer-") as temporary:
        directory = Path(temporary)
        tls_directory = directory / "tls"
        tls_directory.mkdir(mode=0o700)
        tls = certificates(tls_directory)
        keys = {}
        for name in ("account-a", "account-b"):
            keys[name] = directory / (name + "-attester")
            keys[name].mkdir(mode=0o700)
            run([fixture, "--write-request-key", keys[name]])
        for case in cases:
            current = directory / case
            current.mkdir(mode=0o700)
            try:
                exercise(case, current, command, fixture, tls, keys)
            except BaseException as error:
                raise AssertionError("Remote consumer check failed: " + case) from error
    print(f"Remote consumer checks passed: {len(cases)}.")


if __name__ == "__main__":
    main()
