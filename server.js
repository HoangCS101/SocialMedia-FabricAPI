const express = require('express');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const { TextDecoder } = require('util');
const jwt = require('jsonwebtoken') ;
const grpc = require('@grpc/grpc-js');
const { connect, Contract, hash, Identity, Signer, signers } = require('@hyperledger/fabric-gateway');
const FabricCAServices = require('fabric-ca-client');
const { Wallets } = require('fabric-network');


// Secret key for JWT creation and verification.
const SECRET_KEY = 'your_secret_key';

// This part covers the Fabric CA setup
const caURL = 'https://localhost:7054'; // URL của Fabric CA
const ca = new FabricCAServices(caURL);
// ------------------------------

const app = express();
const port = 3000;
app.use(express.json());

// The Fabric channel used.
const channelName = 'mychannel';
// The chaincode (smart contract) deployed.
const chaincodeName = 'basic';
// Membership Service Provider (MSP) identifier.
const mspId = 'Org1MSP';

// Path to crypto materials.
const cryptoPath = path.resolve("D:\\241\\DACN\\Blockchain\\HF\\Telusko\\test\\fabric-samples\\test-network\\organizations\\peerOrganizations\\org1.example.com");

// Path to user private key directory.
const keyDirectoryPath = path.resolve(cryptoPath, 'users', 'User1@org1.example.com', 'msp', 'keystore');

// Path to wallet directory.
const walletPath = './wallet';

// Path to user certificate directory.
const certDirectoryPath = path.resolve(cryptoPath, 'users', 'User1@org1.example.com', 'msp', 'signcerts');

// TLS certificate for secure communication.
const tlsCertPath = path.resolve(cryptoPath, 'peers', 'peer0.org1.example.com', 'tls', 'ca.crt');

// Gateway peer endpoint.
const peerEndpoint = 'localhost:7051';

// Gateway peer SSL host name override.
const peerHostAlias = 'peer0.org1.example.com';

const utf8Decoder = new TextDecoder();
const assetId = `asset${String(Date.now())}`;

// Reads the TLS certificate.
// Establishes a gRPC connection to communicate with the Fabric peer.
async function newGrpcConnection() {
    const tlsRootCert = await fs.readFile(tlsCertPath);
    const tlsCredentials = grpc.credentials.createSsl(tlsRootCert);
    return new grpc.Client(peerEndpoint, tlsCredentials, {
        'grpc.ssl_target_name_override': peerHostAlias,
    });
}

// Reads the certificate in certPath folder.
async function newIdentity() {
    const certPath = await getFirstDirFileName(certDirectoryPath);
    const credentials = await fs.readFile(certPath);
    return { mspId, credentials };
}


app.post('/register', async (req, res) => {
    try {
        const { enrollmentID, role } = req.body;
        if (!enrollmentID || !role) {
            return res.status(400).json({ error: 'enrollmentID and role are required' });
        }

        const wallet = await Wallets.newFileSystemWallet(path.join(__dirname, 'wallet'));

        const adminIdentity = await wallet.get('admin');
        if (!adminIdentity) {
            throw new Error('Admin identity not found in wallet. Please enroll admin first.');
        }

        const provider = wallet.getProviderRegistry().getProvider(adminIdentity.type);
        const adminUser = await provider.getUserContext(adminIdentity, 'admin');

        const enrollmentSecret = await ca.register({
            affiliation: 'org1.department1',
            enrollmentID,
            role,
        }, adminUser);

        res.json({ message: `User ${enrollmentID} registered successfully`, enrollmentSecret });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/enroll', async (req, res) => {
    try {
        const { enrollmentID, enrollmentSecret } = req.body;

        // Mở wallet để lưu chứng chỉ
        const wallet = await Wallets.newFileSystemWallet('./wallet');

        // Kiểm tra user đã enroll chưa
        const userIdentity = await wallet.get(enrollmentID);
        if (userIdentity) {
            return res.status(400).json({ message: `User ${enrollmentID} is already enrolled` });
        }

        // Enroll user
        const enrollment = await ca.enroll({ enrollmentID, enrollmentSecret });

        // Lưu chứng chỉ vào wallet
        const userCert = {
            credentials: {
                certificate: enrollment.certificate,
                privateKey: enrollment.key.toBytes(),
            },
            mspId: 'Org1MSP',
            type: 'X.509',
        };

        await wallet.put(enrollmentID, userCert);

        res.json({
            message: `User ${enrollmentID} enrolled successfully`,
            certificate: enrollment.certificate,
            privateKey: enrollment.key.toBytes()
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Đăng nhập và lấy JWT
app.post('/login', async (req, res) => {
    try {
        const { enrollmentID } = req.body;

        // Mở wallet để kiểm tra chứng chỉ
        const wallet = await Wallets.newFileSystemWallet('./wallet');
        const userIdentity = await wallet.get(enrollmentID);

        if (!userIdentity) {
            return res.status(401).json({ error: 'User not found or not enrolled' });
        }

        // Tạo JWT token
        const token = jwt.sign(
            { enrollmentID, mspId: userIdentity.mspId },
            SECRET_KEY,
            { expiresIn: '1h' } // 🔹 Token có hiệu lực trong 1 giờ
        );

        res.json({
            message: 'Login successful for user ' + enrollmentID,
            token
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/createAdmin', async (req, res) => {
    try {
        const wallet = await Wallets.newFileSystemWallet(walletPath);
        const adminIdentity = await wallet.get('admin');

        if (adminIdentity) {
            return res.status(400).json({ message: 'Admin identity already exists in wallet.' });
        }

        const enrollment = await ca.enroll({ enrollmentID: 'admin', enrollmentSecret: 'adminpw' });

        const identity = {
            credentials: {
                certificate: enrollment.certificate,
                privateKey: enrollment.key.toBytes(),
            },
            mspId: 'Org1MSP',
            type: 'X.509',
        };

        await wallet.put('admin', identity);
        return res.status(200).json({ message: 'Admin identity enrolled successfully' });
    } catch (error) {
        console.error(`Failed to enroll admin: ${error}`);
        return res.status(500).json({ error: `Failed to enroll admin: ${error.message}` });
    }
});

app.get('/identity', async (req, res) => {
    try {
        const identity = await newIdentity();
        res.json({
            mspId: identity.mspId,
            credentials: identity.credentials.toString(), // Converts the certificate to a readable format
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

async function newSigner() {
    const keyPath = await getFirstDirFileName(keyDirectoryPath);
    const privateKeyPem = await fs.readFile(keyPath);
    const privateKey = crypto.createPrivateKey(privateKeyPem);
    return signers.newPrivateKeySigner(privateKey);
}

async function getFirstDirFileName(dirPath) {
    const files = await fs.readdir(dirPath);
    if (!files.length) throw new Error(`No files in directory: ${dirPath}`);
    return path.join(dirPath, files[0]);
}

async function getContract() {
    const client = await newGrpcConnection();
    const gateway = connect({
        client,
        identity: await newIdentity(),
        signer: await newSigner(),
        hash: hash.sha256,
    });
    return gateway.getNetwork(channelName).getContract(chaincodeName);
}

app.get('/assets', async (req, res) => {
    try {
        const contract = await getContract();
        const resultBytes = await contract.evaluateTransaction('GetAllAssets');
        const result = JSON.parse(utf8Decoder.decode(resultBytes));
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/assets', async (req, res) => {
    try {
        const { id, color, size, owner, value } = req.body;
        const contract = await getContract();
        await contract.submitTransaction('CreateAsset', id, color, size, owner, value);
        res.json({ message: 'Asset created successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/assets/:id', async (req, res) => {
    try {
        const contract = await getContract();
        const resultBytes = await contract.evaluateTransaction('ReadAsset', req.params.id);
        const result = JSON.parse(utf8Decoder.decode(resultBytes));
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


app.listen(port, () => {
    console.log(`Fabric API running on port ${port}`);
});