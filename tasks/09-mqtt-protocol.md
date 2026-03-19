# Task 09: MQTT Protocol Fixes

## Summary

Fix MQTT protocol implementation: payload encoding (raw bytes vs hex), SUBSCRIBE flow (missing DISCONNECT), error handling (wrong exit codes), and topic encoding.

## Failing Tests (7)

| Test | Description | Root Cause |
|------|-------------|------------|
| 1132 | MQTT CONNACK with bad Remaining Length | Wrong exit code (56 instead of 8) |
| 1193 | MQTT PUBLISH 2k payload | Newlines in payload encoded as `0a` hex instead of raw bytes |
| 1194 | MQTT SUBSCRIBE with PUBLISH before SUBACK | Wrong SUBSCRIBE/PUBLISH flow |
| 1195 | MQTT SUBSCRIBE with short PUBLISH | Wrong exit code (56 instead of 18) |
| 1196 | MQTT with error in CONNACK | Wrong exit code (56 instead of 73) |
| 1198 | MQTT PUBLISH empty payload, single space topic | Space in topic encoded as `%20` |
| 1199 | MQTT PUBLISH empty payload, no topic | Wrong topic handling |

## Key Changes

### 1. Payload encoding (`crates/liburlx/src/protocol/mqtt.rs`)
MQTT payloads must be sent as raw bytes, not hex-encoded. Newlines (`\n` = 0x0a) must be sent as the actual byte, not as the string "0a".

### 2. Topic encoding
Topic strings must NOT be URL-encoded. A space in the topic should remain a literal space, not `%20`.

### 3. Exit code mapping
Map MQTT errors to correct curl exit codes:
- Bad CONNACK remaining length → exit 8 (`CURLE_WEIRD_SERVER_REPLY`)
- Short PUBLISH (truncated) → exit 18 (`CURLE_PARTIAL_FILE`)
- Error in CONNACK → exit 73 (`CURLE_REMOTE_ACCESS_DENIED`)
- Generic recv error → exit 56 only for actual recv failures

### 4. SUBSCRIBE flow
After SUBSCRIBE, wait for SUBACK before processing PUBLISH messages. Include DISCONNECT at end of session.

## Acceptance Criteria

```bash
cd vendor/curl-build/tests
perl runtests.pl -a -m=30 -c <wrapper> -vc /usr/bin/curl \
  1132 1193 1194 1195 1196 1198 1199
```

All 7 tests must report OK.
