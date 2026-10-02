import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import request from "supertest";
import { app, db } from "../src/app";

// Behavioural contract the Patch Developer must preserve. The DB is stubbed so the
// tests assert on the SQL text and bind values the handlers send.
type Call = { text: string; values?: unknown[] };
let calls: Call[] = [];
const originalQuery = db.query.bind(db);

function stubRows(rows: unknown[]) {
  (db as any).query = async (text: string, values?: unknown[]) => {
    calls.push({ text, values });
    return { rows };
  };
}

afterEach(() => {
  (db as any).query = originalQuery;
  calls = [];
});

test("product search returns matching rows", async () => {
  stubRows([{ id: 1, name: "Lamp", price: 10 }]);
  const res = await request(app).get("/api/products?q=Lamp");
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, [{ id: 1, name: "Lamp", price: 10 }]);
});

test("product search never puts user input in the SQL text", async () => {
  stubRows([]);
  await request(app).get("/api/products?q=' OR 1=1 --");
  assert.ok(!calls[0].text.includes("OR 1=1"), `user input reached SQL text: ${calls[0].text}`);
});

test("invoice requires authentication", async () => {
  const res = await request(app).get("/api/invoices/1");
  assert.equal(res.status, 401);
});

test("owner can read their invoice", async () => {
  stubRows([{ id: 1, owner_id: 7, total: 99 }]);
  const res = await request(app).get("/api/invoices/1").set("x-user-id", "7");
  assert.equal(res.status, 200);
  assert.equal(res.body.total, 99);
});

test("invoice lookup is scoped to the caller", async () => {
  stubRows([]);
  const res = await request(app).get("/api/invoices/1").set("x-user-id", "8");
  assert.equal(res.status, 404);
  assert.ok(calls[0].values?.includes(8), "query must bind the caller id");
});
