import { createHash } from "crypto";

export function createDeviceFingerprint(req: Request): string {
  const components = [
    req.headers.get("x-forwarded-for") ||
      req.headers.get("remoteAddress") ||
      "",
    req.headers.get("user-agent"),
    req.headers.get("accept-language"),
  ];
  return createHash("sha256").update(components.join("|")).digest("hex");
}
