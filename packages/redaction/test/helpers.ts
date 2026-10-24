import { randomBytes } from "node:crypto";

const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const B64URL = `${ALNUM}-_`;

export function rnd(n: number, alphabet: string): string {
  return Array.from(randomBytes(n), (b) => alphabet[b % alphabet.length]).join("");
}

/** Gerçek görünümlü AMA rastgele üretilen sahte jetonlar. Kaynakta tam biçim bulunmaz (parçalardan birleşir). */
export const fake = {
  awsKeyId: (): string => ["AK", "IA"].join("") + rnd(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"),
  githubToken: (): string => ["gh", "p_"].join("") + rnd(36, ALNUM),
  gitlabToken: (): string => ["gl", "pat-"].join("") + rnd(24, B64URL),
  slackToken: (): string => ["xo", "xb-"].join("") + rnd(24, `${ALNUM}-`),
  googleKey: (): string => ["AI", "za"].join("") + rnd(35, B64URL),
  jwt: (): string => `${["ey", "J"].join("")}${rnd(24, B64URL)}.${["ey", "J"].join("")}${rnd(24, B64URL)}.${rnd(32, B64URL)}`,
  highEntropy: (): string => {
    for (;;) {
      const t = rnd(40, ALNUM);
      if (/[A-Z]/.test(t) && /[a-z]/.test(t) && /\d/.test(t)) return t;
    }
  },
  password: (): string => `${rnd(6, "abcdefghjkmnpqrstuvwxyz")}${rnd(4, "23456789")}${rnd(4, "ABCDEFGHJKMNPQRST")}`,
  privateKeyBlock: (): string => {
    const begin = ["-----BEGIN", "RSA", "PRIVATE KEY-----"].join(" ");
    const end = ["-----END", "RSA", "PRIVATE KEY-----"].join(" ");
    const lines = Array.from({ length: 4 }, () => rnd(64, `${ALNUM}+/`));
    return `${begin}\n${lines.join("\n")}\n${end}`;
  },
};
