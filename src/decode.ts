import * as crypto from "crypto";
import * as os from "os";
import * as aws from "aws-sdk";
import * as fs from "fs";

const UNENCRYPTED_SUFFIX = "_unencrypted";

export class SopsError extends Error {}

export interface KmsData {
  arn: string;
  created_at: string;
  enc: string;
  role?: string;
  context?: any;
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
}

export interface EncodedTree {
  sops?: SopsMetadata;
  [key: string]: any;
}
type EncryptionModifier = (key: string) => boolean;
const checkEncryptedSuffix = (modifier: string) => (key: string) =>
  !key.endsWith(modifier);
const checkUnencryptedSuffix = (modifier: string) => (key: string) =>
  key.endsWith(modifier);
const checkUnencryptedRegex = (modifier: string) => (key: string) =>
  new RegExp(modifier).test(key);
const checkEncryptedRegex = (modifier: string) => (key: string) =>
  !new RegExp(modifier).test(key);

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

  const tree = JSON.parse(data.toString());

  return decrypt(tree);
}

/**
 * Decode the given EncodedTree structure as an SOPS block of structured data
 *
 * @param tree data previous read
 */
export async function decrypt(tree: EncodedTree) {
  const { sops } = tree;

  if (!sops) {
    return tree;
  }

  const key = await getKey(tree);

  const encryptionModifier: EncryptionModifier = getEncryptionModifier(sops);

  if (key === null) {
    throw new SopsError("missing key");
  }

  const digest = crypto.createHash("sha512");

  const result = walkAndDecrypt(
    tree,
    key,
    "",
    digest,
    true,
    false,
    encryptionModifier,
  );

  if (sops.mac) {
    const hash: string = decryptScalar(
      sops.mac,
      key,
      sops.lastmodified,
      null,
      false,
    );

    if (hash.toUpperCase() !== digest.digest("hex").toUpperCase()) {
      throw new Error("Hash mismatch");
    }
  }

  return result;
}

// Convert to a string value
function toBytes(value: string | Buffer): string {
  if(typeof value === "boolean"){
    return value === true ? 'True' : 'False';
  }else if (typeof value !== "string") {
    return value.toString();
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
  value: any,
  key: Buffer,
  aad: string,
  digest: crypto.Hash | null,
  unencrypted: boolean,
) {
  if (unencrypted || typeof value !== "string") {
    if (digest) {
      digest.update(toBytes(value));
    }

    return value;
  }

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

  if (digest) {
    digest.update(cleartext);
  }

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
      return cleartext === "True";
    default:
      throw new SopsError(`Unknown type ${valtype}`);
  }
}

function walkAndDecrypt(
  tree: EncodedTree,
  key: Buffer,
  aad = "",
  digest: crypto.Hash,
  isRoot = true,
  unencrypted = false,
  encryptionModifier: EncryptionModifier,
): any {
  const doValue = (
    value: any,
    caad: string,
    unencrypted_branch: boolean,
  ): any => {
    if (Array.isArray(value)) {
      return value.map((vv) => doValue(vv, caad, unencrypted_branch));
    }
    if (typeof value === "object") {
      return walkAndDecrypt(
        value,
        key,
        caad,
        digest,
        false,
        false,
        encryptionModifier,
      );
    }
    return decryptScalar(value, key, caad, digest, unencrypted_branch);
  };

  const result: { [key: string]: any } = {};

  Object.entries(tree).forEach(([k, value]) => {
    if (k === "sops" && isRoot) {
      // The top level 'sops' node is ignored since it's the internal configuration
      return;
    }

    result[k] = doValue(
      value,
      `${aad}${k}:`,
      unencrypted || encryptionModifier(k),
    );
  });

  return result;
}

/**
 * Get the key from the 'sops.kms' node of the tree
 *
 * @param tree
 */
async function getKey(tree: EncodedTree): Promise<Buffer | null> {
  if (!tree.sops || !tree.sops.kms) {
    return null;
  }

  const kmsTree = tree.sops.kms;

  if (!Array.isArray(kmsTree)) {
    return null;
  }

  // eslint-disable-next-line no-restricted-syntax
  for (const entry of kmsTree) {
    if (!entry.enc || !entry.arn) {
      // Invalid format for a KMS node
      // eslint-disable-next-line no-continue
      continue;
    }

    try {
      // eslint-disable-next-line no-await-in-loop
      const kms = await getAwsSessionForEntry(entry);

      // eslint-disable-next-line no-await-in-loop
      const response = await kms
        .decrypt({
          CiphertextBlob: Buffer.from(entry.enc, "base64"),
          EncryptionContext: entry.context || {},
        })
        .promise();

      if (!response.Plaintext || !(response.Plaintext instanceof Buffer)) {
        throw new SopsError("Invalid response");
      }

      return response.Plaintext;
    } catch (err) {
      // log it
    }
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
}): Promise<aws.KMS> {
  // extract the region from the ARN
  // arn:aws:kms:{REGION}:...
  const res = entry.arn.match(/^arn:aws:kms:(.+):([0-9]+):key\/(.+)$/);

  if (!res || res.length < 4) {
    throw new SopsError(`Invalid ARN ${entry.arn} insufficent components`);
  }

  if (!res) {
    throw new SopsError(`Invalid ARN ${entry.arn} in entry`);
  }

  const region = res[1];

  if (!entry.role) {
    // if there are no role to assume, return the client directly
    try {
      const client = new aws.KMS({ region });
      return client;
    } catch (err) {
      throw new SopsError(`Unable to get boto3 client in ${region}`);
    }
  }

  // otherwise, create a client using temporary tokens that assume the role
  try {
    const client = new aws.STS();
    const role = await client
      .assumeRole({
        RoleArn: entry.role,
        RoleSessionName: `sops@${os.hostname()}`,
      })
      .promise();

    try {
      const credentials = role.Credentials;
      if (!credentials) {
        throw new Error("missing credentails");
      }
      const keyid = credentials.AccessKeyId;
      const secretkey = credentials.SecretAccessKey;
      const token = credentials.SessionToken;

      return new aws.KMS({
        region,
        accessKeyId: keyid,
        secretAccessKey: secretkey,
        sessionToken: token,
      });
    } catch (err) {
      throw new SopsError("failed to initialize KMS client");
    }
  } catch (err) {
    throw new SopsError(`Unable to switch roles ${err}`);
  }
}
