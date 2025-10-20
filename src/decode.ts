import * as crypto from "crypto";
import * as os from "os";
import * as fs from "fs";
import { AssumeRoleCommand, STSClient } from "@aws-sdk/client-sts";
import { DecryptCommand, KMSClient } from "@aws-sdk/client-kms";

const UNENCRYPTED_SUFFIX = "_unencrypted";
/**
 *  used to assure that MACs created with mac_only_encrypted
 *  are unique from those created without it.
 *
 *      const value = crypto.createHash('sha256').update('sops').digest();
 */
const MAC_ONLY_ENCRYPTED_INITIALIZATION = Buffer.from(
  "8a3fd2ad54ce66527b1034f3d147be0b0b975b3bf44f72c6fdadec8176f27d69",
  "hex",
);

// Why doesn't the JSON methods return this...
export type Json = string | number | boolean | null | JsonObject | JsonArray;

export type JsonArray = Array<Json>;
export interface JsonObject {
  [property: string]: Json;
}

export class SopsError extends Error {}

export interface KmsData {
  arn: string;
  created_at: string;
  enc: string;
  role?: string;
  context?: Record<string, string>;
}

export interface SopsMetadata {
  kms?: KmsData[];
  mac: string;
  lastmodified: string;
  version: string;
  unencrypted_suffix?: string;
  encrypted_suffix?: string;
  unencrypted_regex?: string;
  encrypted_regex?: string;
  mac_only_encrypted?: boolean;
}

export interface EncodedTree {
  // sops?: SopsMetadata;
  [property: string]: Json | undefined;
}

type EncryptionModifier = (path: string[]) => boolean;
const checkEncryptedSuffix = (modifier: string) => (path: string[]) =>
  path.some((key) => key.endsWith(modifier));
const checkUnencryptedSuffix = (modifier: string) => (path: string[]) =>
  !path.some((key) => key.endsWith(modifier));
const checkUnencryptedRegex = (modifier: string) => {
  const re = new RegExp(modifier);
  return (path: string[]) => !path.some((key) => re.test(key));
};
const checkEncryptedRegex = (modifier: string) => {
  const re = new RegExp(modifier);
  return (path: string[]) => path.some((key) => re.test(key));
};

/**
 * Read the given file from the FileSytem and return the decoded data
 *
 * @param path
 */
export async function decodeFile(path: string) {
  const data = await new Promise<Buffer>((resolve, reject) => {
    fs.readFile(path, (err, contents) => {
      if (err) {
        reject(err);
      } else {
        resolve(contents);
      }
    });
  });

  const tree: Json = JSON.parse(data.toString());

  if (typeof tree === "object" && !Array.isArray(tree) && tree !== null) {
    return decrypt(tree);
  }
  return tree;
}

/**
 * Decode the given EncodedTree structure as an SOPS block of structured data
 *
 * @param tree data previous read
 */
export async function decrypt(tree: JsonObject) {
  const { sops } = tree as { sops?: SopsMetadata };

  if (!sops) {
    return tree;
  }

  const key = await getKey(tree);

  const shouldBeEncrypted: EncryptionModifier = getEncryptionModifier(sops);

  if (key === null) {
    throw new SopsError("missing key");
  }

  const digest = crypto.createHash("sha512");

  const macOnlyEncrypted = sops.mac_only_encrypted;
  if (macOnlyEncrypted) {
    digest.update(MAC_ONLY_ENCRYPTED_INITIALIZATION);
  }
  const settings = { key, digest, shouldBeEncrypted, macOnlyEncrypted };
  const result = walkAndDecrypt(tree, [], settings);

  if (sops.mac) {
    const hash = String(decryptScalar(sops.mac, key, sops.lastmodified));

    if (hash.toUpperCase() !== digest.digest("hex").toUpperCase()) {
      throw new Error("Hash mismatch");
    }
  }

  return result;
}

// Convert to a string value
function toBytes(value: unknown): string {
  if (value === undefined || value === null) {
    return "";
  } else if (typeof value === "boolean") {
    return value === true ? "True" : "False";
  } else if (typeof value !== "string") {
    return typeof value?.toString === "function"
      ? value.toString()
      : String(value);
  }

  return value;
}

// Given a sops config, return the appropriate encryption modifier
function getEncryptionModifier(
  sops: SopsMetadata | undefined,
): EncryptionModifier {
  if (sops?.encrypted_regex) {
    return checkEncryptedRegex(sops?.encrypted_regex);
  }
  if (sops?.encrypted_suffix) {
    return checkEncryptedSuffix(sops?.encrypted_suffix);
  }
  if (sops?.unencrypted_regex) {
    return checkUnencryptedRegex(sops?.unencrypted_regex);
  }
  return checkUnencryptedSuffix(sops?.unencrypted_suffix || UNENCRYPTED_SUFFIX);
}

/**
 *  Decrypt a single value, update the digest if provided
 */
export function decryptScalar(
  value: string,
  key: Uint8Array,
  aad: string,
): string | boolean | number {
  const valre = value.match(
    /^ENC\[AES256_GCM,data:(.+),iv:(.+),tag:(.+),type:(.+)\]/,
  );
  if (!valre) {
    return value;
  }

  const encValue = Buffer.from(valre[1], "base64");
  const iv = Buffer.from(valre[2], "base64");
  const tag = Buffer.from(valre[3], "base64");
  const valtype = valre[4];

  const decryptor = crypto.createDecipheriv("aes-256-gcm", key, iv);

  decryptor.setAuthTag(tag);
  decryptor.setAAD(Buffer.from(aad));

  const cleartext =
    decryptor.update(encValue, undefined, "utf8") + decryptor.final("utf8");

  switch (valtype) {
    case "bytes":
      return cleartext;
    case "str":
      return cleartext;
    case "int":
      return parseInt(cleartext, 10);
    case "float":
      return parseFloat(cleartext);
    case "bool":
      return cleartext.toLowerCase() === "true";
    default:
      throw new SopsError(`Unknown type ${valtype}`);
  }
}

interface WalkSettings {
  key: Uint8Array;
  digest: crypto.Hash;
  shouldBeEncrypted: EncryptionModifier;
  macOnlyEncrypted?: boolean;
}

function walkAndDecrypt(
  value: Json,
  path: string[],
  settings: WalkSettings,
): unknown {
  const { key, digest, shouldBeEncrypted, macOnlyEncrypted } = settings;
  if (value === null) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((v) => walkAndDecrypt(v, path, settings));
  }
  if (typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([k, v]) => v !== undefined && (path.length || k !== "sops"))
        .map(([k, v]) => [k, walkAndDecrypt(v, [...path, k], settings)]),
    );
  }
  const isEncrypted = shouldBeEncrypted(path);
  const plaintext =
    typeof value === "string" && isEncrypted
      ? decryptScalar(value, key, path.join(":") + ":")
      : value;
  if (!macOnlyEncrypted || isEncrypted) {
    digest.update(toBytes(plaintext));
  }
  return plaintext;
}

/**
 * Get the key from the 'sops.kms' node of the tree
 *
 * @param tree
 */
async function getKey(tree: EncodedTree): Promise<Uint8Array | null> {
  const { sops } = tree as { sops?: SopsMetadata };

  if (!sops || !sops.kms) {
    return null;
  }

  const kmsTree = sops.kms;

  if (!Array.isArray(kmsTree)) {
    return null;
  }

  const errors: string[] = [];

  // eslint-disable-next-line no-restricted-syntax
  for (const entry of kmsTree) {
    try {
      if (!entry.enc || !entry.arn) {
        throw new SopsError(
          `Invalid format for KMS node: ${JSON.stringify(entry)}`,
        );
      }

      // eslint-disable-next-line no-await-in-loop
      const kms = await getAwsSessionForEntry(entry);

      // eslint-disable-next-line no-await-in-loop
      const command = new DecryptCommand({
        CiphertextBlob: Buffer.from(entry.enc, "base64"),
        EncryptionContext: entry.context || {},
      });

      const response = await kms.send(command);

      if (!response.Plaintext || !(response.Plaintext instanceof Uint8Array)) {
        throw new SopsError("Invalid plaintext in KMS response");
      }

      return response.Plaintext;
    } catch (error) {
      const [errorType, errorText] =
        error instanceof Error
          ? [error.name, error.message]
          : ["UnknownError", JSON.stringify(error)];
      errors.push(`${entry.arn} - ${errorType}: ${errorText}`);
    }
  }
  if (errors.length > 0) {
    throw new SopsError(`Failed to get key: \n  ${errors.join("\n  ")}`);
  }
  return null;
}

/**
 * Return a boto3 session using a role if one exists in the entry
 * @param entry
 */
async function getAwsSessionForEntry(entry: {
  arn: string;
  role?: string;
}): Promise<KMSClient> {
  // extract the region from the ARN
  // arn:aws:kms:{REGION}:...
  const res = entry.arn.match(/^arn:aws:kms:(.+):([0-9]+):(key|alias)\/(.+)$/);

  if (!res || res.length < 5) {
    throw new SopsError(`Invalid ARN ${entry.arn} insufficent components`);
  }

  if (!res) {
    throw new SopsError(`Invalid ARN ${entry.arn} in entry`);
  }

  const region = res[1];

  if (!entry.role) {
    // if there are no role to assume, return the client directly
    try {
      const client = new KMSClient({ region });
      return client;
    } catch (err) {
      throw new SopsError(`Unable to get boto3 client in ${region}`);
    }
  }

  // otherwise, create a client using temporary tokens that assume the role
  try {
    const stsClient = new STSClient({ region });

    const command = new AssumeRoleCommand({
      RoleArn: entry.role,
      RoleSessionName: `sops@${os.hostname()}`,
    });
    const role = await stsClient.send(command);

    try {
      const credentials = role.Credentials;
      if (!credentials) {
        throw new Error("missing credentails");
      }
      const accessKeyId = credentials.AccessKeyId;
      const secretAccessKey = credentials.SecretAccessKey;
      const sessionToken = credentials.SessionToken;

      if (!accessKeyId || !secretAccessKey) {
        throw new Error("missing credentail values");
      }

      const client = new KMSClient({
        region,
        credentials: { accessKeyId, secretAccessKey, sessionToken },
      });

      return client;
    } catch (err) {
      throw new SopsError("failed to initialize KMS client");
    }
  } catch (err) {
    throw new SopsError(`Unable to switch roles ${err}`);
  }
}
