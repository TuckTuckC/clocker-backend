const express = require('express');
require('dotenv').config();

const app = express();

app.use(express.json()); // for parsing application/json

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
