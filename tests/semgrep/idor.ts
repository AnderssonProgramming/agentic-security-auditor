// Annotated fixtures for `semgrep --test --config auditor/rules tests/semgrep`.
import express from "express";

const app = express();
declare const Invoice: any;
declare const db: any;

app.get("/invoices/:id", async (req, res) => {
  // ruleid: express-idor-unscoped-lookup-by-id
  const invoice = await Invoice.findById(req.params.id);
  res.json(invoice);
});

app.get("/orders/:id", async (req, res) => {
  // ruleid: express-idor-unscoped-lookup-by-id
  const { rows } = await db.query("SELECT * FROM orders WHERE id = $1", [req.params.id]);
  res.json(rows[0]);
});

app.get("/scoped/:id", async (req, res) => {
  // ok: express-idor-unscoped-lookup-by-id
  const { rows } = await db.query("SELECT * FROM orders WHERE id = $1 AND owner_id = $2", [req.params.id, req.user.id]);
  res.json(rows[0]);
});

app.get("/owned/:id", async (req, res) => {
  // ok: express-idor-unscoped-lookup-by-id
  const invoice = await Invoice.findOne({ id: req.params.id, ownerId: req.user.id });
  res.json(invoice);
});
