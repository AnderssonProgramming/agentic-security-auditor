// Annotated fixtures for `semgrep --test --config auditor/rules tests/semgrep`.
import express from "express";
import { Pool } from "pg";

const app = express();
const db = new Pool();

app.get("/a", async (req, res) => {
  // ruleid: node-sqli-raw-query-string-building
  const r = await db.query(`SELECT * FROM t WHERE name = '${req.query.name}'`);
  res.json(r.rows);
});

app.get("/b", async (req, res) => {
  // ruleid: node-sqli-raw-query-string-building
  const r = await db.query("SELECT * FROM t WHERE id = " + req.params.id);
  res.json(r.rows);
});

app.get("/c", async (req, res) => {
  // ok: node-sqli-raw-query-string-building
  const r = await db.query("SELECT * FROM t WHERE id = $1", [req.params.id]);
  res.json(r.rows);
});

app.get("/d", async (req, res) => {
  // ok: node-sqli-raw-query-string-building
  const r = await db.query(`SELECT * FROM t LIMIT ${Number(req.query.limit)}`);
  res.json(r.rows);
});
