const FabricCAServices = require('fabric-ca-client');
const { Wallets } = require('fabric-network');
const fs = require('fs');
const path = require('path');

async function enrollAdmin() {
    try {
        const caURL = 'https://localhost:7054'; // URL của Fabric CA
        const ca = new FabricCAServices(caURL);

        const wallet = await Wallets.newFileSystemWallet('./wallet');
        const adminIdentity = await wallet.get('admin');

        if (adminIdentity) {
            console.log('Admin identity already exists');
            return;
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
        console.log('Admin identity enrolled successfully');
    } catch (error) {
        console.error(`Failed to enroll admin: ${error}`);
    }
}

enrollAdmin();