import express, { type Express } from "express";
import { config } from "./utils/config";
import cors from "cors";
import helmet from "helmet";
import { connectDB } from "./config/database";

const app: Express = express();

app.use(cors({}));
app.use(helmet());

const PORT = config.PORT || 3001;
connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Bugkhoj server is running at ${PORT}`);
  });
});
