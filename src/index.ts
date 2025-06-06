import express, {
  type Express,
  Request,
  Response,
  NextFunction,
} from "express";
import { config } from "./utils/config";
import logger from "./utils/logger";
import authRoutes from "./routes/auth";
import cors from "cors";
import helmet from "helmet";
import { connectDB } from "./config/database";
import { loginLimiter } from "./middleware/ratelimiter";

const app: Express = express();

const CORS_WHITELIST = [
  "http://localhost:4001",
  "https://bugkhoji.com",
  "https://www.bugkhoji.com",
];

app.use(helmet());

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);

      if (CORS_WHITELIST.indexOf(origin) === -1) {
        return callback(new Error("Not allowed by CORS"), false);
      }

      return callback(null, true);
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE"],
  })
);

app.use(express.json());
app.use("/v1", authRoutes);
app.use("/login/researcher", loginLimiter);
app.use("/login/admin", loginLimiter);

app.use((err: any, req: Request, res: Response, next: NextFunction): void => {
  logger.error(`${err.message} - ${req.method} ${req.originalUrl} - ${req.ip}`);

  if (err.message === "Not allowed by CORS") {
    res.status(403).json({ message: err.message });
    return;
  }

  res.status(500).json({ message: "Internal Server Error" });
});

const PORT = config.PORT;
connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Bugkhoj server is running at ${PORT}`);
  });
});
