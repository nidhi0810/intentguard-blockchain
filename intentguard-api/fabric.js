
'use strict';

const fs = require('fs');
const grpc = require('@grpc/grpc-js');
const { connect, signers } = require('@hyperledger/fabric-gateway');
const crypto = require('crypto');

const testNetwork = `${process.env.HOME}/fabric-dev/fabric-samples/test-network`;
const orgPath = `${testNetwork}/organizations/peerOrganizations/org1.example.com`;

const certPath = `${orgPath}/users/User1@org1.example.com/msp/signcerts/cert.pem`;
const keyDir = `${orgPath}/users/User1@org1.example.com/msp/keystore`;
const tlsCertPath = `${orgPath}/peers/peer0.org1.example.com/tls/ca.crt`;

function newGrpcConnection() {
    const tlsRootCert = fs.readFileSync(tlsCertPath);
    const credentials = grpc.credentials.createSsl(tlsRootCert);

    return new grpc.Client('localhost:7051', credentials, {
        'grpc.ssl_target_name_override': 'peer0.org1.example.com',
    });
}

function newIdentity() {
    return {
        mspId: 'Org1MSP',
        credentials: fs.readFileSync(certPath),
    };
}

function newSigner() {
    const files = fs.readdirSync(keyDir);
    if (files.length === 0) {
        throw new Error('No private key found in Fabric keystore');
    }

    const privateKeyPem = fs.readFileSync(`${keyDir}/${files[0]}`);
    const privateKey = crypto.createPrivateKey(privateKeyPem);

    return signers.newPrivateKeySigner(privateKey);
}

async function connectToFabric() {
    const client = newGrpcConnection();

    const gateway = connect({
        client,
        identity: newIdentity(),
        signer: newSigner(),
    });

    const network = gateway.getNetwork('intentguard');
    const contract = network.getContract('intentguard');

    return { client, gateway, contract };
}

module.exports = { connectToFabric };
