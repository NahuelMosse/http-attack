Review this route handler for security bugs:

```js
app.get("/users/:id", (req, res) => db.query(`SELECT * FROM users WHERE id = ${req.params.id}`).then((r) => res.json(r)));
```
