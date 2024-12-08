import express from "express";
import cors from "cors";
import { Coinbase, Wallet } from "@coinbase/coinbase-sdk";
import crypto from "crypto";
import admin from "firebase-admin";
import { encodeFunctionData, namehash } from "viem";
import { normalize } from "viem/ens";
import multer from "multer";
import ecies from "eciesjs";

const app = express();

app.use(cors());
app.use(express.json());

const storage = multer.memoryStorage();
const upload = multer({ storage });

Coinbase.configureFromJson({
  filePath:
    "C:/Users/Pareekshit Joshi/Documents/Development/Node/cdp/cdp_api_key.json",
});

admin.initializeApp({
  credential: admin.credential.cert(
    "C:/Users/Pareekshit Joshi/Documents/Development/Node/cdp/firebase.json"
  ),
});

const db = admin.firestore();

app.post("/wallet/create", async (req, res) => {
  const { passwordHash } = req.body;
  const { walletId, seed, address, publicKeyHex } = await createWallet();

  const encryptedSeed = encryptSeed(passwordHash, seed);
  await storeEncryptedSeed(address, {
    ...encryptedSeed,
    walletId,
    publicKeyHex,
  });
  res.send({ address });
});

app.post("/wallet/fund", async (req, res) => {
  const { address, passwordHash } = req.body;

  const txn = await fundWallet(address, passwordHash);
  console.log(txn);
  if (!txn) {
    res.send({ status: "error" });
    return;
  }
  res.send({ status: "success" });
});

app.post("/basename/register", async (req, res) => {
  const { address, passwordHash, name } = req.body;

  const txnLink = await registerBaseName(name, address, passwordHash);

  if (!txnLink) {
    res.send({ status: "error" });
    return;
  }

  res.send({ txnLink });
});

app.get("/media/list", async (req, res) => {
  const { address } = req.query;
  const list = await fetchMediaList(address);
  if (!list) {
    res.send({ status: "error" });
    return;
  }
  res.send(list);
});

app.post("/media/upload", upload.single("file"), async (req, res) => {
  const { address } = req.body;
  const [_, publicKeyHex] = await fetchWalletFromPasswordHash(address, null);
  if (!publicKeyHex) {
    res.send({ status: "error" });
    return;
  }

  const publicKey = Buffer.from(publicKeyHex, "hex");
  const file = req.file;
  const { key, iv, encryptedMedia } = await encryptMedia(file.buffer);
  const encryptedKey = ecies.encrypt(publicKey, key);
  const blobId = await uploadToWalrus(encryptedMedia);
  const doc = await storeMediaMetadata(
    address,
    file.originalname,
    file.mimetype,
    encryptedKey.toString("base64"),
    iv.toString("base64"),
    blobId
  );
  if (!doc) {
    res.send({ status: "error" });
    return;
  }
  res.send({ blobId });
});

app.post("/media/download", async (req, res) => {
  const { address, passwordHash, blobId } = req.body;
  const doc = await fetchMediaMetadata(address, blobId);
  if (!doc) {
    res.send({ status: "Media not found" });
    return;
  }
  const [wallet] = await fetchWalletFromPasswordHash(address, passwordHash);
  if (!wallet) {
    res.send({ status: "error" });
    return;
  }
  const privateKeyHex = Array.from(wallet.master.privateKey)
    .map((byte) => byte.toString(16).padStart(2, "0")) // Convert each byte to hex
    .join("");
  const privateKey = Buffer.from(privateKeyHex, "hex");
  const media = await downloadFromWalrus(blobId);
  if (!media) {
    res.send({ status: "error" });
    return;
  }
  const { fileName, mimeType, encryptedKey, iv } = doc;
  const encryptedKeyBuffer = Buffer.from(encryptedKey, "base64");
  const ivBuffer = Buffer.from(iv, "base64");
  const decryptedKey = ecies.decrypt(privateKey, encryptedKeyBuffer);
  const decryptedMedia = await decryptMedia(decryptedKey, ivBuffer, media);
  res.setHeader("Content-Type", mimeType);
  res.setHeader("Content-Disposition", `attachment; filename=${fileName}`);

  res.send(decryptedMedia);
});

app.post("/media/shareAccess", async (req, res) => {
  const { address, passwordHash, blobId, destinationAddress } = req.body;
  const response = await fetchMediaMetadata(address, blobId);
  if (!response) {
    res.send({ status: "Media not found" });
    return;
  }
  const [wallet] = await fetchWalletFromPasswordHash(address, passwordHash);
  if (!wallet) {
    res.send({ status: "error" });
    return;
  }
  const privateKeyHex = Array.from(wallet.master.privateKey)
    .map((byte) => byte.toString(16).padStart(2, "0")) // Convert each byte to hex
    .join("");
  const privateKey = Buffer.from(privateKeyHex, "hex");
  const { fileName, mimeType, encryptedKey, iv } = response;
  const encryptedKeyBuffer = Buffer.from(encryptedKey, "base64");
  const decryptedKey = ecies.decrypt(privateKey, encryptedKeyBuffer);
  const [_, publicKeyHex] = await fetchWalletFromPasswordHash(
    destinationAddress,
    null
  );
  if (!publicKeyHex) {
    res.send({ status: "error" });
    return;
  }
  const destinationPublicKey = Buffer.from(publicKeyHex, "hex");
  const encryptedKeyAgain = ecies.encrypt(destinationPublicKey, decryptedKey);
  const doc = await storeMediaMetadata(
    destinationAddress,
    fileName,
    mimeType,
    encryptedKeyAgain.toString("base64"),
    iv,
    blobId
  );
  if (!doc) {
    res.send({ status: "error" });
    return;
  }
  res.send({ status: "success" });
});

app.listen(3000, () => {
  console.log("App listening on port 3000!");
});

async function createWallet() {
  let wallet = await Wallet.create();
  const publicKeyHex = Array.from(wallet.master.publicKey)
    .map((byte) => byte.toString(16).padStart(2, "0")) // Convert each byte to hex
    .join(""); // Combine into a single string;
  const address = (await wallet.getDefaultAddress()).getId();
  let data = wallet.export();
  return { ...data, address, publicKeyHex };
}

async function fetchWallet(walletId, seed) {
  const fetchedWallet = await Wallet.fetch(walletId);
  if (seed) {
    fetchedWallet.setSeed(seed);
  }
  return fetchedWallet;
}

function encryptSeed(passwordHash, seed) {
  const salt = crypto.randomBytes(16);
  const key = crypto.pbkdf2Sync(passwordHash, salt, 100000, 32, "sha256"); // 256-bit key
  const iv = crypto.randomBytes(16);

  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  const encryptedSeed = Buffer.concat([
    cipher.update(seed, "utf8"),
    cipher.final(),
  ]);
  return {
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    encryptedSeed: encryptedSeed.toString("base64"),
  };
}

function decryptSeed(passwordHash, encryptedSeed) {
  const salt = Buffer.from(encryptedSeed.salt, "base64");
  const iv = Buffer.from(encryptedSeed.iv, "base64");
  const encryptedSeedBuffer = Buffer.from(
    encryptedSeed.encryptedSeed,
    "base64"
  );

  const key = crypto.pbkdf2Sync(passwordHash, salt, 100000, 32, "sha256"); // 256-bit key
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  try {
    const decryptedSeed = Buffer.concat([
      decipher.update(encryptedSeedBuffer),
      decipher.final(),
    ]);
    return decryptedSeed.toString("utf8");
  } catch (error) {
    console.error(error);
  }
  return null;
}

async function storeEncryptedSeed(address, encryptedSeed) {
  const docRef = await db.collection("wallets").doc(address).set(encryptedSeed);
}

async function fetchMediaList(address) {
  const querySnapshot = await db
    .collection("users")
    .doc(address)
    .collection("media")
    .get();

  const mediaList = [];
  querySnapshot.docs.forEach((doc) => {
    mediaList.push(doc.id);
  });

  return mediaList;
}

async function fetchEncryptedSeed(address) {
  const docRef = db.collection("wallets").doc(address);
  const doc = await docRef.get();
  return doc.data();
}

async function fetchWalletFromPasswordHash(address, passwordHash) {
  const encryptedSeed = await fetchEncryptedSeed(address);
  if (!encryptedSeed) {
    console.log("Wallet not found");
    return;
  }

  let wallet = null;
  if (passwordHash) {
    const seed = decryptSeed(passwordHash, encryptedSeed);
    if (!seed) {
      console.log("Invalid password");
      return;
    }
    wallet = await fetchWallet(encryptedSeed.walletId, seed);
  }
  return [wallet, encryptedSeed.publicKeyHex];
}

async function registerBaseName(name, address, passwordHash) {
  try {
    const [wallet] = await fetchWalletFromPasswordHash(address, passwordHash);
    if (!wallet) {
      return;
    }
    const registerArgs = createRegisterContractMethodArgs(name, address);
    const contractInvocation = await wallet.invokeContract({
      contractAddress: BaseNamesRegistrarControllerAddress,
      method: "register",
      abi: registrarABI,
      args: registerArgs,
      amount: 0.002,
      assetId: Coinbase.assets.Eth,
    });

    await contractInvocation.wait();

    const txnLink = contractInvocation.getTransactionLink();

    console.log(
      `Successfully registered Basename ${registerArgs.request[0]} with TxnLink : ${txnLink} for wallet: `,
      wallet
    );
    return txnLink;
  } catch (error) {
    console.error(`Error registering a Basename`, error);
  }
}

async function encryptMedia(media) {
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  const encryptedMedia = Buffer.concat([cipher.update(media), cipher.final()]);
  return {
    key: key,
    iv: iv,
    encryptedMedia: encryptedMedia,
  };
}

async function decryptMedia(key, iv, encryptedMedia) {
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  const decryptedMedia = Buffer.concat([
    decipher.update(encryptedMedia),
    decipher.final(),
  ]);
  return decryptedMedia;
}

async function uploadToWalrus(media) {
  try {
    const response = await fetch("http://127.0.0.1:31415/v1/store", {
      method: "PUT",
      body: media,
    });

    if (response.ok) {
      const res = await response.json();
      console.log(res);
      if (res.newlyCreated) {
        const blobId = res.newlyCreated.blobObject.blobId;
        return blobId;
      }
      if (res.alreadyCertified) {
        const blobId = res.alreadyCertified.blobId;
        return blobId;
      }
    } else {
      console.error("Error uploading file:", response.statusText);
    }
  } catch (error) {
    console.error("Error uploading file:", error);
  }
}

async function downloadFromWalrus(blobId) {
  try {
    const response = await fetch(`http://127.0.0.1:31415/v1/${blobId}`);
    if (response.ok) {
      const data = await response.arrayBuffer();
      return Buffer.from(data); // Convert array buffer to a Node.js Buffer
    } else {
      console.error("Error downloading file:", response.statusText);
    }
  } catch (error) {
    console.error("Error downloading file:", error);
  }
}

async function storeMediaMetadata(
  address,
  fileName,
  mimeType,
  encryptedKey,
  iv,
  blobId
) {
  const doc = await db
    .collection("users")
    .doc(address)
    .collection("media")
    .doc(blobId)
    .set({
      fileName,
      mimeType,
      encryptedKey,
      iv,
      blobId,
    });
  return doc;
}

async function fetchMediaMetadata(address, blobId) {
  const docRef = db
    .collection("users")
    .doc(address)
    .collection("media")
    .doc(blobId);
  const doc = await docRef.get();
  return doc.data();
}

// Base Sepolia Registrar Controller Contract Address.
const BaseNamesRegistrarControllerAddress =
  "0x49aE3cC2e3AA768B1e5654f5D3C6002144A59581";

// Base Sepolia L2 Resolver Contract Address.
const L2ResolverAddress = "0x6533C94869D28fAA8dF77cc63f9e2b2D6Cf77eBA";

// The regular expression to validate a Basename on Base Sepolia.
const baseNameRegex = /\.basetest\.eth$/;

// Relevant ABI for L2 Resolver Contract.
const l2ResolverABI = [
  {
    inputs: [
      { internalType: "bytes32", name: "node", type: "bytes32" },
      { internalType: "address", name: "a", type: "address" },
    ],
    name: "setAddr",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      { internalType: "bytes32", name: "node", type: "bytes32" },
      { internalType: "string", name: "newName", type: "string" },
    ],
    name: "setName",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
];

// Relevant ABI for Basenames Registrar Controller Contract.
const registrarABI = [
  {
    inputs: [
      {
        components: [
          {
            internalType: "string",
            name: "name",
            type: "string",
          },
          {
            internalType: "address",
            name: "owner",
            type: "address",
          },
          {
            internalType: "uint256",
            name: "duration",
            type: "uint256",
          },
          {
            internalType: "address",
            name: "resolver",
            type: "address",
          },
          {
            internalType: "bytes[]",
            name: "data",
            type: "bytes[]",
          },
          {
            internalType: "bool",
            name: "reverseRecord",
            type: "bool",
          },
        ],
        internalType: "struct RegistrarController.RegisterRequest",
        name: "request",
        type: "tuple",
      },
    ],
    name: "register",
    outputs: [],
    stateMutability: "payable",
    type: "function",
  },
];

// Create register contract method arguments.
function createRegisterContractMethodArgs(baseName, addressId) {
  const addressData = encodeFunctionData({
    abi: l2ResolverABI,
    functionName: "setAddr",
    args: [namehash(normalize(baseName)), addressId],
  });
  const nameData = encodeFunctionData({
    abi: l2ResolverABI,
    functionName: "setName",
    args: [namehash(normalize(baseName)), baseName],
  });

  const registerArgs = {
    request: [
      baseName.replace(baseNameRegex, ""),
      addressId,
      "31557600",
      L2ResolverAddress,
      [addressData, nameData],
      true,
    ],
  };
  console.log(`Register contract method arguments constructed: `, registerArgs);

  return registerArgs;
}

async function fundWallet(address, passwordHash) {
  const [wallet] = await fetchWalletFromPasswordHash(address, passwordHash);
  if (!wallet) {
    console.log("Wallet not found");
    return;
  }
  return await wallet.faucet();
}
