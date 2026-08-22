import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const C = require("../../src/demo_server/static/comments.js");

const TEXT = "alpha beta gamma beta delta beta epsilon";

test("captureQuote records exact text with affixes", () => {
  const q = C.captureQuote(TEXT, 6, 10);
  assert.equal(q.exact, "beta");
  assert.equal(q.prefix, "alpha ");
  assert.equal(q.suffix.slice(0, 6), " gamma");
});

test("resolveQuote finds a unique match", () => {
  const q = C.captureQuote("one two three", 4, 7);
  assert.deepEqual(C.resolveQuote("one two three", q), { start: 4, end: 7 });
});

test("resolveQuote disambiguates repeats using affixes", () => {
  const q = C.captureQuote(TEXT, 17, 21); // the second "beta"
  assert.deepEqual(C.resolveQuote(TEXT, q), { start: 17, end: 21 });
});

test("resolveQuote survives edits away from the anchor", () => {
  const q = C.captureQuote(TEXT, 17, 21);
  const edited = "PREFIX ADDED " + TEXT;
  assert.deepEqual(C.resolveQuote(edited, q), { start: 30, end: 34 });
});

test("resolveQuote returns null when the text is gone", () => {
  const q = C.captureQuote(TEXT, 6, 10);
  assert.equal(C.resolveQuote("nothing matching here", q), null);
});

test("newCommentId is unique and prefixed", () => {
  const a = C.newCommentId();
  const b = C.newCommentId();
  assert.match(a, /^c_[0-9a-z]+$/);
  assert.notEqual(a, b);
});
