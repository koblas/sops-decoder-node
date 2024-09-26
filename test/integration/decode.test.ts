import * as assert from "assert";
import { execFile } from "child_process";
import { randomUUID } from "crypto";
import * as test from "node:test";
import { tmpdir } from "os";
import * as path from "path";
import { decodeFile } from "../../src/decode";
import { readFile, rm, writeFile } from "fs/promises";

const mustEnv = (name: string) => {
  const value = process.env[name];
  if (!value) {
    throw new Error(`missing required environment variable: '${name}'`);
  }
  return value;
};

type SopsArgs = {
  data: Record<string, unknown>;
  encryptionMethod: {
    kms?: string[];
  };
  keyEncryptionBasis: {
    unencrypted_suffix?: string;
    encrypted_suffix?: string;
    unencrypted_regex?: string;
    encrypted_regex?: string;
  };
  macOnlyEncrypted?: boolean;
};

const createEncryptedFile = async ({
  data,
  encryptionMethod,
  keyEncryptionBasis,
  macOnlyEncrypted,
}: SopsArgs) => {
  const filepath = path.join(tmpdir(), `${randomUUID()}.json`);
  const opts: string[] = [];
  if (encryptionMethod.kms) {
    opts.push(...encryptionMethod.kms.flatMap((key) => ["-k", key]));
  }
  if (keyEncryptionBasis.unencrypted_suffix) {
    opts.push("--unencrypted-suffix", keyEncryptionBasis.unencrypted_suffix);
  }
  if (keyEncryptionBasis.encrypted_suffix) {
    opts.push("--encrypted-suffix", keyEncryptionBasis.encrypted_suffix);
  }
  if (keyEncryptionBasis.unencrypted_regex) {
    opts.push("--unencrypted-regex", keyEncryptionBasis.unencrypted_regex);
  }
  if (keyEncryptionBasis.encrypted_regex) {
    opts.push("--encrypted-regex", keyEncryptionBasis.encrypted_regex);
  }
  if (macOnlyEncrypted) {
    opts.push("--mac-only-encrypted");
  }
  await writeFile(filepath, JSON.stringify(data));
  const child = execFile("sops", [...opts, "-e", "-i", filepath]);
  await new Promise((res, rej) =>
    child.on("exit", (code) => (code === 0 ? res(null) : rej(code))),
  );
  test.after(async () => rm(filepath));
  return filepath;
};

test.test("decodeFile", { concurrency: true, timeout: 2000 }, async (t) => {
  //  We cannot test without this
  if (!process.env["KMS_KEY_ARN"]) {
    return;
  }

  const simpleArray = ["value", false, 21, null];
  const simpleObject = {
    myString: "string",
    myNumber: 42,
    myBool: true,
    myNull: null,
  };
  const strings = {
    myString: "string",
    myString_plain: "string",
    myString_encrypted: "string",
  };
  const bools = {
    myBool: true,
    myBool_plain: true,
    myBool_encrypted: true,
  };
  const numbers = {
    myNumber: 42,
    myNumber_plain: 42,
    myNumber_encrypted: 42,
  };
  const nulls = {
    myNull: null,
    myNull_plain: null,
    myNull_encrypted: null,
  };
  const arrays = {
    myArray: simpleArray,
    myArray_plain: simpleArray,
    myArray_encrypted: simpleArray,
  };
  const objects = {
    myObject: simpleObject,
    myObject_plain: simpleObject,
    myObject_encrypted: simpleObject,
  };

  const kmsEncryption = { kms: [mustEnv("KMS_KEY_ARN")] };
  const encryptionMethods: SopsArgs["encryptionMethod"][] = [kmsEncryption];
  const keyEncryptionBases: SopsArgs["keyEncryptionBasis"][] = [
    { unencrypted_suffix: "_plain" },
    { encrypted_suffix: "_encrypted" },
    { unencrypted_regex: "_plain$" },
    { encrypted_regex: "_encrypted$" },
  ];
  const dataOptions: Record<string, Record<string, unknown>> = {
    strings,
    bools,
    numbers,
    nulls,
    arrays,
    objects,
  };

  await Promise.all([
    t.test(
      "key encryption bases (arbitrarily choosing encryption method)",
      async (t) => {
        const encryptionMethod = kmsEncryption;
        await Promise.all(
          keyEncryptionBases.map((keyEncryptionBasis) =>
            t.test(`using ${JSON.stringify(keyEncryptionBasis)}`, async (t) => {
              await Promise.all(
                Object.entries(dataOptions).map(async ([name, data]) =>
                  t.test(`with ${name} data`, async (t) => {
                    const filepath = await createEncryptedFile({
                      data,
                      encryptionMethod,
                      keyEncryptionBasis,
                    });
                    const decoded = await decodeFile(filepath);
                    assert.deepEqual(decoded, data);
                  }),
                ),
              );
            }),
          ),
        );
      },
    ),
    t.test(
      "encryption methods (arbitrarily choosing key encryption basis)",
      async (t) => {
        const keyEncryptionBasis = keyEncryptionBases[0];
        await Promise.all(
          encryptionMethods.map((encryptionMethod) =>
            t.test(
              `using ${Object.keys(encryptionMethod)[0]} encryption`,
              async (t) => {
                await Promise.all(
                  Object.entries(dataOptions).map(async ([name, data]) =>
                    t.test(`with ${name} data`, async (t) => {
                      const filepath = await createEncryptedFile({
                        data,
                        encryptionMethod,
                        keyEncryptionBasis,
                      });
                      const decoded = await decodeFile(filepath);
                      assert.deepEqual(decoded, data);
                    }),
                  ),
                );
              },
            ),
          ),
        );
      },
    ),
    t.test("mac only encrypted", async (t) => {
      const encryptionMethod = kmsEncryption;
      const keyEncryptionBasis = { encrypted_suffix: "a" };
      type Data = { a: string; b: number };
      const data: Data = { a: "string", b: 2 };
      const options = [
        { macOnlyEncrypted: true, changes: true, error: false },
        { macOnlyEncrypted: true, changes: false, error: false },
        { macOnlyEncrypted: false, changes: true, error: true },
        { macOnlyEncrypted: false, changes: false, error: false },
      ] as const;
      await Promise.all(
        options.map(({ macOnlyEncrypted, changes, error }) =>
          t.test(
            `${macOnlyEncrypted ? "enabled" : "disabled"}, ${
              changes ? "with" : "without"
            } changes to unencrypted data, ${
              error ? "expecting error" : "expecting success"
            }`,
            async (t) => {
              const filepath = await createEncryptedFile({
                data,
                encryptionMethod,
                keyEncryptionBasis,
                macOnlyEncrypted,
              });
              if (changes) {
                const fileContents = JSON.parse(
                  await readFile(filepath, "utf8"),
                ) as Data;
                fileContents.b = 42;
                await writeFile(filepath, JSON.stringify(fileContents));
              }
              if (error) {
                try {
                  await decodeFile(filepath);
                  throw new Error("expected an error");
                } catch (e) {
                  assert(
                    e instanceof Error && e.message.includes("Hash mismatch"),
                    "expected a hash-mismatch error",
                  );
                }
              } else {
                const decoded = (await decodeFile(filepath)) as Data;
                assert(
                  decoded.b === (changes ? 42 : data.b),
                  "expected the decoded data to match the file contents",
                );
              }
            },
          ),
        ),
      );
    }),
  ]);
});
