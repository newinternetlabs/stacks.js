import { testables } from '../src/cli';
import { getNetwork, CLINetworkAdapter, CLI_NETWORK_OPTS } from '../src/network';
import { CLI_CONFIG_TYPE } from '../src/argparse';

import * as fixtures from './fixtures/cli.fixture';
import inquirer from 'inquirer';
import {
  ClarityAbi,
  createStacksPrivateKey,
  publicKeyFromSignature,
  signWithKey,
  verifySignature
} from '@stacks/transactions';
import {readFileSync} from 'fs';
import path from 'path';
import fetchMock from 'jest-fetch-mock';
import { makekeychainTests, keyInfoTests, MakeKeychainResult, WalletKeyInfoResult } from './derivation-path/keychain';
import { subdomainOpToZFPieces, SubdomainOp } from '../src/utils';
import * as crypto from 'crypto';

const TEST_ABI: ClarityAbi = JSON.parse(readFileSync(path.join(__dirname, './abi/test-abi.json')).toString());
const TEST_FEE_ESTIMATE = JSON.parse(readFileSync(path.join(__dirname, './fee-estimate/test-fee-estimate.json')).toString());
jest.mock('inquirer');

const { addressConvert, contractFunctionCall, makeKeychain, getStacksWalletKey, preorder, register, migrateSubdomains } = testables as any;

const mainnetNetwork = new CLINetworkAdapter(
  getNetwork({} as CLI_CONFIG_TYPE, false),
  {} as CLI_NETWORK_OPTS
);

const testnetNetwork = new CLINetworkAdapter(
  getNetwork({} as CLI_CONFIG_TYPE, true),
  {} as CLI_NETWORK_OPTS
);

describe('convert_address', () => {
  test.each(fixtures.convertAddress)('%p - testnet: %p', async (input, testnet, expectedResult) => {
    const network = testnet ? testnetNetwork : mainnetNetwork;
    const result = await addressConvert(network, [input]);
    expect(JSON.parse(result)).toEqual(expectedResult);
  });
});

describe('Contract function call', () => {
  test('Should accept string-ascii clarity type argument', async () => {
    const contractAddress = 'STB44HYPYAT2BB2QE513NSP81HTMYWBJP02HPGK6';
    const contractName = 'test-contract-name';
    const functionName = 'test-func-string-ascii-argument';
    const fee = 200;
    const nonce = 0;
    const privateKey = 'cb3df38053d132895220b9ce471f6b676db5b9bf0b4adefb55f2118ece2478df01';
    const args = [
      contractAddress,
      contractName,
      functionName,
      fee,
      nonce,
      privateKey
    ];
    const contractInputArg = { currency: 'USD' };

    // @ts-ignore
    inquirer.prompt = jest.fn().mockResolvedValue(contractInputArg);

    fetchMock.once(JSON.stringify(TEST_ABI)).once('success');

    const txid = '0x6c764e276b500babdac6cec159667f4b68938d31eee82419473a418222af7d5d';
    const result = await contractFunctionCall(testnetNetwork, args);

    expect(result.txid).toEqual(txid);
  });

  test('Should accept string-utf8 clarity type argument', async () => {
    const contractAddress = 'STB44HYPYAT2BB2QE513NSP81HTMYWBJP02HPGK6';
    const contractName = 'test-contract-name';
    const functionName = 'test-func-string-utf8-argument';
    const fee = 210;
    const nonce = 1;
    const privateKey = 'cb3df38053d132895220b9ce471f6b676db5b9bf0b4adefb55f2118ece2478df01';
    const args = [
      contractAddress,
      contractName,
      functionName,
      fee,
      nonce,
      privateKey
    ];
    const contractInputArg = { msg: 'plain text' };

    // @ts-ignore
    inquirer.prompt = jest.fn().mockResolvedValue(contractInputArg);

    fetchMock.once(JSON.stringify(TEST_ABI)).once('success');

    const txid = '0x97f41dfa44a5833acd9ca30ffe31d7137623c0e31a5c6467daeed8e61a03f51c';
    const result = await contractFunctionCall(testnetNetwork, args);

    expect(result.txid).toEqual(txid);
  });

  test('Should accept optional clarity type argument', async () => {
    const contractAddress = 'STB44HYPYAT2BB2QE513NSP81HTMYWBJP02HPGK6';
    const contractName = 'test-contract-name';
    const functionName = 'test-func-optional-argument';
    const fee = 220;
    const nonce = 2;
    const privateKey = 'cb3df38053d132895220b9ce471f6b676db5b9bf0b4adefb55f2118ece2478df01';
    const args = [
      contractAddress,
      contractName,
      functionName,
      fee,
      nonce,
      privateKey
    ];
    const contractInputArg = { optional: 'optional string-utf8 string' };

    // @ts-ignore
    inquirer.prompt = jest.fn().mockResolvedValue(contractInputArg);

    fetchMock.once(JSON.stringify(TEST_ABI)).once('success');

    const txid = '0x5fc468f21345c5ecaf1c007fce9630d9a79ec1945ed8652cc3c42fb542e35fe2';
    const result = await contractFunctionCall(testnetNetwork, args);

    expect(result.txid).toEqual(txid);
  });

  test('Should accept primitive clarity type arguments', async () => {
    const contractAddress = 'STB44HYPYAT2BB2QE513NSP81HTMYWBJP02HPGK6';
    const contractName = 'test-contract-name';
    const functionName = 'test-func-primitive-argument';
    const fee = 230;
    const nonce = 3;
    const privateKey = 'cb3df38053d132895220b9ce471f6b676db5b9bf0b4adefb55f2118ece2478df01';
    const args = [
      contractAddress,
      contractName,
      functionName,
      fee,
      nonce,
      privateKey
    ];
    const contractInputArg = {
      amount: 1000,
      address: 'STB44HYPYAT2BB2QE513NSP81HTMYWBJP02HPGK6',
      exists: false,
    };

    // @ts-ignore
    inquirer.prompt = jest.fn().mockResolvedValue(contractInputArg);

    fetchMock.once(JSON.stringify(TEST_ABI)).once('success');

    const txid = '0x94b1cfab79555b8c6725f19e4fcd6268934d905578a3e8ef7a1e542b931d3676';
    const result = await contractFunctionCall(testnetNetwork, args);

    expect(result.txid).toEqual(txid);
  });

  test('Should accept buffer clarity type argument', async () => {
    const contractAddress = 'STB44HYPYAT2BB2QE513NSP81HTMYWBJP02HPGK6';
    const contractName = 'test-contract-name';
    const functionName = 'test-func-buffer-argument';
    const fee = 240;
    const nonce = 4;
    const privateKey = 'cb3df38053d132895220b9ce471f6b676db5b9bf0b4adefb55f2118ece2478df01';
    const args = [
      contractAddress,
      contractName,
      functionName,
      fee,
      nonce,
      privateKey
    ];
    const contractInputArg = {
      bufferArg: 'string buffer'
    };

    // @ts-ignore
    inquirer.prompt = jest.fn().mockResolvedValue(contractInputArg);

    fetchMock.once(JSON.stringify(TEST_ABI)).once('success');

    const txid = '0x6b6cd5bfb44c46a68090f0c5f659e9cc02518eafab67b0b740e1e77a55bbf284';
    const result = await contractFunctionCall(testnetNetwork, args);

    expect(result.txid).toEqual(txid);
  });
});

describe('Keychain custom derivation path', () => {
  test.each(makekeychainTests)('Make keychain using custom derivation path %#', async (derivationPath: string, keyChainResult: MakeKeychainResult) => {
    const encrypted = 'vim+XrRNSm+SqSn0MyWNEi/e+UK5kX8WGCLE/sevT6srZG+quzpp911sWP0CcvsExCH1M4DgOfOldMitLdkq1b6rApDwtAcOWdAqiaBk37M=';
    const args = [encrypted, derivationPath];

    // Mock TTY
    process.stdin.isTTY = true;
    process.env.password = 'supersecret';

    const keyChain = await makeKeychain(testnetNetwork, args);
    const result = JSON.parse(keyChain);
    expect(result).toEqual(keyChainResult);
    // Unmock TTY
    process.stdin.isTTY = false;
    process.env.password = undefined;
  });

  test.each(keyInfoTests)('Make keychain using custom derivation path %#', async (derivationPath: string, walletInfoResult: WalletKeyInfoResult ) => {
    const encrypted = 'vim+XrRNSm+SqSn0MyWNEi/e+UK5kX8WGCLE/sevT6srZG+quzpp911sWP0CcvsExCH1M4DgOfOldMitLdkq1b6rApDwtAcOWdAqiaBk37M=';
    const args = [encrypted, derivationPath];

    // Mock TTY
    process.stdin.isTTY = true;
    process.env.password = 'supersecret';

    const walletKey = await getStacksWalletKey(testnetNetwork, args);
    const result = JSON.parse(walletKey);
    expect(result).toEqual([
      walletInfoResult
    ]);
    // Unmock TTY
    process.stdin.isTTY = false;
    process.env.password = undefined;
  });
});

describe('BNS', () => {
  test('buildRegisterNameTx', async () => {
    const fullyQualifiedName = 'test.id';
    const ownerKey = '0d146cf7289dd0b6f41385b0dbc733167c5dffc6534c59cafd63a615f59095d8';
    const salt =  'salt';
    const zonefile = 'zonefile';

    const args = [
      fullyQualifiedName,
      ownerKey,
      salt,
      zonefile,
    ];

    const mockedResponse = JSON.stringify(TEST_FEE_ESTIMATE);

    fetchMock.mockOnce(mockedResponse);
    fetchMock.mockOnce(JSON.stringify({ nonce: 1000 }));
    fetchMock.mockOnce(JSON.stringify('success'));

    const txResult = await register(testnetNetwork, args);

    expect(txResult.txid).toEqual('0xsuccess');
  });

  test('buildPreorderNameTx', async () => {
    const fullyQualifiedName = 'test.id';
    const privateKey = '0d146cf7289dd0b6f41385b0dbc733167c5dffc6534c59cafd63a615f59095d8';
    const salt =  'salt';
    const stxToBurn = '1000';

    const args = [
      fullyQualifiedName,
      privateKey,
      salt,
      stxToBurn,
    ];

    const mockedResponse = JSON.stringify(TEST_FEE_ESTIMATE);

    fetchMock.mockOnce(mockedResponse);
    fetchMock.mockOnce(JSON.stringify({ nonce: 1000 }));
    fetchMock.mockOnce(JSON.stringify('success'));

    const txResult = await preorder(testnetNetwork, args);

    expect(txResult.txid).toEqual('0xsuccess');
  });
});

describe('Subdomain Migration', () => {
  // Consider test scenarios for subdomain migration
  const subDomainTestData: Array<[string, string, string, { txid: string, error: string | null, status: number }]> = [
    [
      'sound idle panel often situate develop unit text design antenna vendor screen opinion balcony share trigger accuse scatter visa uniform brass update opinion media',
      'test1.id.stx', // Subdomain to be migrated: success
      'ST3WTH31TWVYDD1YGYKSZK8XFJ3Z1Z5JMGGRF4558', // Owner will match
      { txid: 'success', error: null, status: 200 } // expected output, successfully migrated
    ],
    [
      'sound idle panel often situate develop unit text design antenna vendor screen opinion balcony share trigger accuse scatter visa uniform brass update opinion media',
      'test2.id.stx', // Subdomain to be migrated
      'ST3Q2T3380WE1K5PW72R6R76Q8HRPEK8HR02W6V1M', // Owner mismatch
      { txid: 'error', error: 'Only owner of subdoamin can invoke the transfer operation', status: 400 } // expected output, not migrated due to owner mismatch
    ]
  ];

  // Perform test on subdomain migration command
  test.each(subDomainTestData)('Transfer subdomains to wallet-key addresses that correspond to all data-key addresses', async (mnemonic, subdomain, owner, expected) => {
    const args = [ mnemonic ];
    // Mock gaia hub response during restore wallet
    const mockGaiaHubInfo = JSON.stringify({
      read_url_prefix: 'https://gaia.blockstack.org/hub/',
      challenge_text: '["gaiahub","0","gaia-0","blockstack_storage_please_sign"]',
      latest_auth_version: 'v1',
    });

    fetchMock
      .once(mockGaiaHubInfo)
      .once(JSON.stringify('no found'), { status: 404 }) // legacy wallet config
      .once(JSON.stringify({ names: [ subdomain ] })) // resolve username of this account
      .once(JSON.stringify('ok')) // updateWalletConfig
      .once(JSON.stringify({ names: [ subdomain ]})) // to be migrated
      .once(JSON.stringify({ names: [ 'test3.id.stx', 'test4.id.stx' ]})) // already found subdomain at wallet key address
      .once(JSON.stringify({
        address: owner,
        blockchain: "stacks",
        last_txid: "0x0db9d08ee00bff3cfaeb8c881a1d6391ae974cd8e9143ecb4b60eb1ceb57fbc9",
        resolver: "https://registrar.stacks.co",
        status: "registered_subdomain",
        zonefile: "$ORIGIN test1.id.stx\n$TTL 3600\n_http._tcp\tIN\tURI\t10\t1\t\"https://gaia.blockstack.org/hub/12imq5x4FdqMJVdLAsaRnWTe662ddyWJRT/profile.json\"\n\n",
        zonefile_hash: "4f1f4fdd335e66b9798e0b86cf337d7a"
      }))
      .once(JSON.stringify(expected), { status: expected.status });
    const promptName = subdomain.replaceAll('.', '_');
    const contractInputArg: { [key: string]: boolean } = {};
    // Mock the user input as yes to migrate the subdomain
    contractInputArg[promptName] = true;

    // @ts-ignore
    inquirer.prompt = jest.fn().mockResolvedValue(contractInputArg);

    const output = await migrateSubdomains(testnetNetwork, args);

    expect(JSON.parse(output)).toEqual(expected);
    fetchMock.resetMocks();
  });

  test('Subdomain signature verification', () => {
    const privateKey = 'a5c61c6ca7b3e7e55edee68566aeab22e4da26baa285c7bd10e8d2218aa3b229';
    // Generate Subdomain Operation payload starting with signature
    const subDomainOp: SubdomainOp = {
      subdomainName: 'test.id.stx',
      owner: 'ST3WTH31TWVYDD1YGYKSZK8XFJ3Z1Z5JMGGRF4558',
      zonefile: "$ORIGIN test1.id.stx\n$TTL 3600\n_http._tcp\tIN\tURI\t10\t1\t\"https://gaia.blockstack.org/hub/12imq5x4FdqMJVdLAsaRnWTe662ddyWJRT/profile.json\"\n\n",
      sequenceNumber: 1,
    };
    const subdomainPieces = subdomainOpToZFPieces(subDomainOp);
    const textToSign = subdomainPieces.txt.join(',');
    // Generate signature: https://docs.stacks.co/build-apps/references/bns#subdomain-lifecycle
    /**
     * *********************** IMPORTANT **********************************************
     * subdomain operation will only be accepted if it has a later "sequence=" number,*
     * and a valid signature in "sig=" over the transaction body .The "sig=" field    *
     * includes both the public key and signature, and the public key must hash to    *
     * the previous subdomain operation's "addr=" field                               *
     * ********************************************************************************
     */
    const hash = crypto.createHash('sha256').update(textToSign).digest('hex');
    const sig = signWithKey(createStacksPrivateKey(privateKey), hash);

    subDomainOp.signature = sig.data; // Assign signature to subDomainOp

    // Verify that the generated signature is valid
    const pubKey = publicKeyFromSignature(hash, sig);
    // Skip the recovery params bytes from signature and then verify
    const isValid = verifySignature(subDomainOp.signature.slice(2), hash, pubKey);

    expect(isValid).toEqual(true);
  });
});
