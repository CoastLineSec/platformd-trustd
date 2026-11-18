/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <systemd/sd-varlink-idl.h>

static SD_VARLINK_DEFINE_METHOD(GetBootEvidence,
        SD_VARLINK_DEFINE_OUTPUT(bootId, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT(machineId, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT(osId, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT(osName, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT(osVersion, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT(firmware, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT(secureBoot, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT(tpmPresent, SD_VARLINK_BOOL, 0),
        SD_VARLINK_DEFINE_OUTPUT(measuredBootAvailable, SD_VARLINK_BOOL, 0),
        SD_VARLINK_DEFINE_OUTPUT(evidenceQuality, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(Pcr,
        SD_VARLINK_DEFINE_FIELD(index, SD_VARLINK_INT, 0),
        SD_VARLINK_DEFINE_FIELD(sha256, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(GetMeasuredBoot,
        SD_VARLINK_DEFINE_OUTPUT(available, SD_VARLINK_BOOL, 0),
        SD_VARLINK_DEFINE_OUTPUT(pcrBank, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(pcrs, Pcr, SD_VARLINK_ARRAY),
        SD_VARLINK_DEFINE_OUTPUT(eventLogPresent, SD_VARLINK_BOOL, 0),
        SD_VARLINK_DEFINE_OUTPUT(bootQuality, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT(evidenceQuality, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(Session,
        SD_VARLINK_DEFINE_FIELD(id, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_FIELD(uid, SD_VARLINK_INT, 0),
        SD_VARLINK_DEFINE_FIELD(user, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_FIELD(seat, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_FIELD(type, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_FIELD(class, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_FIELD(state, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_FIELD(active, SD_VARLINK_BOOL, 0),
        SD_VARLINK_DEFINE_FIELD(remote, SD_VARLINK_BOOL, 0),
        SD_VARLINK_DEFINE_FIELD(locked, SD_VARLINK_BOOL, 0),
        SD_VARLINK_DEFINE_FIELD(lockState, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_FIELD(secondsSinceVerification, SD_VARLINK_INT, 0),
        SD_VARLINK_DEFINE_FIELD(verificationRealtimeUSec, SD_VARLINK_INT, 0),
        SD_VARLINK_DEFINE_FIELD(verificationSource, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_FIELD(verificationQuality, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_FIELD(tty, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_FIELD(leader, SD_VARLINK_INT, 0),
        SD_VARLINK_DEFINE_FIELD(userVerified, SD_VARLINK_BOOL, 0),
        SD_VARLINK_DEFINE_FIELD(userSource, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_FIELD(evidenceQuality, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(ListSessions,
        SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(sessions, Session, SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_METHOD(GetSessionTrust,
        SD_VARLINK_DEFINE_INPUT(sessionId, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(session, Session, 0));

static SD_VARLINK_DEFINE_METHOD(GetUserIdentity,
        SD_VARLINK_DEFINE_INPUT(uid, SD_VARLINK_INT, 0),
        SD_VARLINK_DEFINE_OUTPUT(userName, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT(uid, SD_VARLINK_INT, 0),
        SD_VARLINK_DEFINE_OUTPUT(source, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT(verified, SD_VARLINK_BOOL, 0),
        SD_VARLINK_DEFINE_OUTPUT(signingKey, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT(identityQuality, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(PolicyResult,
        SD_VARLINK_DEFINE_FIELD(policyId, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_FIELD(sessionId, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_FIELD(result, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_FIELD(reasonCode, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_FIELD(reason, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_FIELD(windowSec, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_METHOD(EvaluatePolicy,
        SD_VARLINK_DEFINE_INPUT(policy, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_INPUT(sessionId, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(result, PolicyResult, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(AuthEvent,
        SD_VARLINK_DEFINE_FIELD(user, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_FIELD(uid, SD_VARLINK_INT, 0),
        SD_VARLINK_DEFINE_FIELD(pamService, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_FIELD(tty, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_FIELD(remoteHost, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_FIELD(phase, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_FIELD(declaredMethod, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_FIELD(result, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_FIELD(sessionId, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_FIELD(qualifiesForFreshness, SD_VARLINK_BOOL, 0),
        SD_VARLINK_DEFINE_FIELD(realtimeUSec, SD_VARLINK_INT, 0),
        SD_VARLINK_DEFINE_FIELD(evidenceQuality, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(SubmitAuthEvent,
        SD_VARLINK_DEFINE_INPUT(user, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_INPUT(uid, SD_VARLINK_INT, 0),
        SD_VARLINK_DEFINE_INPUT(pamService, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_INPUT(tty, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_INPUT(remoteHost, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_INPUT(phase, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_INPUT(declaredMethod, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_INPUT(result, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_INPUT(sessionId, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(ListAuthEvents,
        SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(events, AuthEvent, SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_STRUCT_TYPE(RuntimeEvent,
        SD_VARLINK_DEFINE_FIELD(description, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_FIELD(digest, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_FIELD(realtimeUSec, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_METHOD(GetRuntimeLog,
        SD_VARLINK_DEFINE_OUTPUT(format, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT(nvIndex, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT(baseline, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT(current, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(events, RuntimeEvent, SD_VARLINK_ARRAY),
        SD_VARLINK_DEFINE_OUTPUT(complete, SD_VARLINK_BOOL, 0),
        SD_VARLINK_DEFINE_OUTPUT(evidenceQuality, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(Attest,
        SD_VARLINK_DEFINE_INPUT(nonceHex, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT(akPublicHex, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT(quotedHex, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT(signatureHex, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT(eventLogHex, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT(pcrBank, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT(evidenceQuality, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(GetAttestationToken,
        SD_VARLINK_DEFINE_INPUT(nonceHex, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT(eat, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT(format, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT(evidenceQuality, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(GetEnrollment,
        SD_VARLINK_DEFINE_OUTPUT(ekPublicHex, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT(ekCertHex, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT(akPublicHex, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT(akNameHex, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT(evidenceQuality, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(ActivateCredential,
        SD_VARLINK_DEFINE_INPUT(credentialHex, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_INPUT(secretHex, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT(challengeHex, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT(evidenceQuality, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_ERROR(NoSuchSession);

static SD_VARLINK_DEFINE_ERROR(UnknownPolicy);

static SD_VARLINK_DEFINE_ERROR(PermissionDenied);

static SD_VARLINK_DEFINE_ERROR(InvalidAuthEvent);

static SD_VARLINK_DEFINE_ERROR(AttestationUnsupported);

static SD_VARLINK_DEFINE_ERROR(AttestationFailed);

static SD_VARLINK_DEFINE_INTERFACE(io_platformd_Trust, "io.platformd.Trust",
        &vl_method_GetBootEvidence,
        &vl_type_Pcr,
        &vl_method_GetMeasuredBoot,
        &vl_type_Session,
        &vl_method_ListSessions,
        &vl_method_GetSessionTrust,
        &vl_method_GetUserIdentity,
        &vl_type_PolicyResult,
        &vl_method_EvaluatePolicy,
        &vl_type_AuthEvent,
        &vl_method_SubmitAuthEvent,
        &vl_method_ListAuthEvents,
        &vl_type_RuntimeEvent,
        &vl_method_GetRuntimeLog,
        &vl_method_Attest,
        &vl_method_GetAttestationToken,
        &vl_method_GetEnrollment,
        &vl_method_ActivateCredential,
        &vl_error_NoSuchSession,
        &vl_error_UnknownPolicy,
        &vl_error_PermissionDenied,
        &vl_error_InvalidAuthEvent,
        &vl_error_AttestationUnsupported,
        &vl_error_AttestationFailed);
