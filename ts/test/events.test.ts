import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyEvent, KitSignatureError, EventMemberAdded } from "../src/index.js";

// The vector internal/events/events_test.go signs with the kit's Go code.
const body = `{"id":"evt_1","type":"member.added","product":"mail","created_at":"2026-10-01T00:00:00Z","data":{"user_id":"u1"}}`;
const header = "t=1759300000,v1=7b00e5e89ca2ca499b0c469b96e045bab5e64ae571aeb68d4e94c90d4d4f3325";
const at = 1759300000 * 1000;

test("verifies what the kit signs (shared vector)", async () => {
  const ev = await verifyEvent("kwh_vector", header, body, at);
  assert.equal(ev.id, "evt_1");
  assert.equal(ev.type, EventMemberAdded);
  assert.deepEqual(ev.data, { user_id: "u1" });
  // Bytes work as well as a string; a second v1 (rotation) is fine.
  await verifyEvent("kwh_vector", "t=1759300000,v1=00ff," + header.split(",")[1], new TextEncoder().encode(body), at);
});

test("refuses anything else", async () => {
  const cases: Array<[string, string, string, string, number]> = [
    ["wrong secret", "kwh_other", header, body, at],
    ["tampered body", "kwh_vector", header, body.replace("u1", "u2"), at],
    ["stale", "kwh_vector", header, body, at + 301_000],
    ["future", "kwh_vector", header, body, at - 301_000],
    ["no header", "kwh_vector", "", body, at],
    ["no v1", "kwh_vector", "t=1759300000", body, at],
    ["short v1", "kwh_vector", "t=1759300000,v1=7b00", body, at],
  ];
  for (const [name, secret, h, b, now] of cases) {
    await assert.rejects(verifyEvent(secret, h, b, now), KitSignatureError, name);
  }
});
