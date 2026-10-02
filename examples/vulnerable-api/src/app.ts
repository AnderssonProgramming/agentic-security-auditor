// Intentionally vulnerable demo service used as an audit target. Do NOT deploy.
import express, { NextFunction, Request, Response } from "express";
import { Pool } from "pg";

type AuthedRequest = Request & { user?: { id: number } };

export const db = new Pool({ connectionString: process.env.DATABASE_URL });
export const app = express();
app.use(express.json());

// Toy auth: trusts a header. Real services use sessions / JWT.
app.use((req: AuthedRequest, _res: Response, next: NextFunction) => {
  const uid = Number(req.header("x-user-id"));
  if (Number.isInteger(uid)) req.user = { id: uid };
  next();
});

// VULN 1 (CWE-89): ORM-less query built with a template literal.
app.get("/api/products", async (req: Request, res: Response) => {
  const { rows } = await db.query(`SELECT id, name, price FROM products WHERE name ILIKE '%${req.query.q}%'`);
  res.json(rows);
});

// VULN 2 (CWE-639, IDOR): any authenticated user can read any invoice by id.
app.get("/api/invoices/:id", async (req: AuthedRequest, res: Response) => {
  if (!req.user) return res.status(401).json({ error: "unauthenticated" });
  const { rows } = await db.query("SELECT * FROM invoices WHERE id = $1", [req.params.id]);
  if (rows.length === 0) return res.status(404).json({ error: "not found" });
  res.json(rows[0]);
});
