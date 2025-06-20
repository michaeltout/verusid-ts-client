/// <reference types="node" />
import { AxiosRequestConfig } from "axios";
import { GetIdentityResponse, LoginConsentRequest, LoginConsentChallenge, LoginConsentProvisioningRequest, LoginConsentProvisioningChallenge, LoginConsentResponse, LoginConsentDecision, LoginConsentProvisioningDecision, LoginConsentProvisioningResponse, SignedSessionObject, SignedSessionObjectData, VerusPayInvoice, VerusPayInvoiceDetails, Identity, GetAddressUtxosResponse, FundRawTransactionResponse, IdentityUpdateRequest, IdentityUpdateRequestDetails, IdentityUpdateResponse, IdentityUpdateResponseDetails } from "verus-typescript-primitives";
import { VerusdRpcInterface } from "verusd-rpc-ts-client";
import BigNumber from "bignumber.js";
declare class VerusIdInterface {
    interface: VerusdRpcInterface;
    constructor(chain: string, baseURL: string, config?: AxiosRequestConfig);
    getCurrentHeight(): Promise<number>;
    getChainId(): Promise<string>;
    signMessage(iAddrOrIdentity: string, message: string, primaryAddrWif: string, getIdentityResult?: GetIdentityResponse["result"], currentHeight?: number, chainIAddr?: string): Promise<string>;
    signHash(iAddrOrIdentity: string, hash: Buffer, primaryAddrWif: string, getIdentityResult?: GetIdentityResponse["result"], currentHeight?: number, chainIAddr?: string): Promise<string>;
    private signHashOrMessage;
    verifyMessage(iAddrOrIdentity: string, base64Sig: string, message: string, getIdentityResult?: GetIdentityResponse["result"], chainIAddr?: string): Promise<boolean>;
    verifyHash(iAddrOrIdentity: string, base64Sig: string, hash: Buffer, getIdentityResult?: GetIdentityResponse["result"], chainIAddr?: string): Promise<boolean>;
    private verifyHashOrMessage;
    getSignatureInfo(iAddrOrIdentity: string, base64Sig: string, chainIAddr?: string): Promise<{
        version: number;
        hashtype: number;
        height: number;
    }>;
    signLoginConsentRequest(request: LoginConsentRequest, primaryAddrWif: string, getIdentityResult?: GetIdentityResponse["result"], currentHeight?: number): Promise<LoginConsentRequest>;
    signIdentityUpdateRequest(request: IdentityUpdateRequest, primaryAddrWif: string, getIdentityResult?: GetIdentityResponse["result"], currentHeight?: number): Promise<IdentityUpdateRequest>;
    createLoginConsentRequest(signingId: string, challenge: LoginConsentChallenge, primaryAddrWif?: string, getIdentityResult?: GetIdentityResponse["result"], currentHeight?: number, chainIAddr?: string): Promise<LoginConsentRequest>;
    createIdentityUpdateRequest(signingId: string, details: IdentityUpdateRequestDetails, primaryAddrWif?: string, getIdentityResult?: GetIdentityResponse["result"], currentHeight?: number, chainIAddr?: string): Promise<IdentityUpdateRequest>;
    verifyLoginConsentRequest(request: LoginConsentRequest, getIdentityResult?: GetIdentityResponse["result"], chainIAddr?: string, sigBlockTime?: number): Promise<boolean>;
    verifyIdentityUpdateRequest(request: IdentityUpdateRequest, getIdentityResult?: GetIdentityResponse["result"], chainIAddr?: string, sigBlockTime?: number): Promise<boolean>;
    private signLoginResponse;
    signIdentityUpdateResponse(response: IdentityUpdateResponse, primaryAddrWif: string, getIdentityResult?: GetIdentityResponse["result"], currentHeight?: number): Promise<IdentityUpdateResponse>;
    private createLoginResponse;
    createIdentityUpdateResponse(signingId: string, details: IdentityUpdateResponseDetails, primaryAddrWif?: string, getIdentityResult?: GetIdentityResponse["result"], currentHeight?: number, chainIAddr?: string): Promise<IdentityUpdateResponse>;
    private verifyResponse;
    verifyIdentityUpdateResponse(response: IdentityUpdateResponse, getIdentityResult?: GetIdentityResponse["result"], chainIAddr?: string, sigBlockTime?: number): Promise<boolean>;
    verifySignedSessionObject(object: SignedSessionObject, getIdentityResult?: GetIdentityResponse["result"], chainIAddr?: string): Promise<boolean>;
    signSessionObject(object: SignedSessionObject, primaryAddrWif: string, getIdentityResult?: GetIdentityResponse["result"], currentHeight?: number): Promise<SignedSessionObject>;
    createSignedSessionObject(signingId: string, data: SignedSessionObjectData, primaryAddrWif?: string, getIdentityResult?: GetIdentityResponse["result"], currentHeight?: number, chainIAddr?: string): Promise<SignedSessionObject>;
    signLoginConsentResponse(response: LoginConsentResponse, primaryAddrWif: string, getIdentityResult?: GetIdentityResponse["result"], currentHeight?: number): Promise<LoginConsentResponse>;
    createLoginConsentResponse(signingId: string, decision: LoginConsentDecision, primaryAddrWif?: string, getIdentityResult?: GetIdentityResponse["result"], currentHeight?: number, chainIAddr?: string): Promise<LoginConsentResponse>;
    verifyLoginConsentResponse(response: LoginConsentResponse, getIdentityResult?: GetIdentityResponse["result"], chainIAddr?: string): Promise<boolean>;
    createVerusPayInvoice(details: VerusPayInvoiceDetails, signingIdIAddr?: string, primaryAddrWif?: string, getIdentityResult?: GetIdentityResponse["result"], currentHeight?: number, chainIAddr?: string): Promise<VerusPayInvoice>;
    signVerusPayInvoice(invoice: VerusPayInvoice, signingIdIAddr: string, systemIdIAddr: string, primaryAddrWif: string, getIdentityResult?: GetIdentityResponse["result"], currentHeight?: number): Promise<VerusPayInvoice>;
    verifySignedVerusPayInvoice(invoice: VerusPayInvoice, getIdentityResult?: GetIdentityResponse["result"], chainIAddr?: string): Promise<boolean>;
    signVerusIdProvisioningResponse(response: LoginConsentProvisioningResponse, primaryAddrWif: string, getIdentityResult?: GetIdentityResponse["result"], currentHeight?: number): Promise<LoginConsentProvisioningResponse>;
    createVerusIdProvisioningResponse(signingId: string, decision: LoginConsentProvisioningDecision, primaryAddrWif?: string, getIdentityResult?: GetIdentityResponse["result"], currentHeight?: number, chainIAddr?: string): Promise<LoginConsentProvisioningResponse>;
    verifyVerusIdProvisioningResponse(response: LoginConsentProvisioningResponse, getIdentityResult?: GetIdentityResponse["result"], chainIAddr?: string): Promise<boolean>;
    static signHashWithAddress(hash: Buffer, wif: string): string;
    static signVerusIdProvisioningRequest(request: LoginConsentProvisioningRequest, addrWif: string): Promise<LoginConsentProvisioningRequest>;
    static createVerusIdProvisioningRequest(signingAddress: string, challenge: LoginConsentProvisioningChallenge, addrWif?: string): Promise<LoginConsentProvisioningRequest>;
    static verifyVerusIdProvisioningRequest(request: LoginConsentProvisioningRequest, address: string): Promise<LoginConsentProvisioningRequest>;
    createUpdateIdentityTransaction(identity: Identity | IdentityUpdateRequestDetails, changeAddress: string, rawIdentityTransaction: string, identityTransactionHeight: number, utxoList?: GetAddressUtxosResponse["result"], chainIAddr?: string, fee?: number, fundRawTransactionResult?: FundRawTransactionResponse["result"], currentHeight?: number, updateIdentityTransactionHex?: string, parseVdxfObjects?: boolean): Promise<{
        hex: string;
        utxos: GetAddressUtxosResponse["result"];
        identity: Identity;
        deltas: Map<string, BigNumber>;
    }>;
    createRevokeIdentityTransaction(_identity: Identity, changeAddress: string, rawIdentityTransaction: string, identityTransactionHeight: number, utxoList?: GetAddressUtxosResponse["result"], chainIAddr?: string, fee?: number, fundRawTransactionResult?: FundRawTransactionResponse["result"], currentHeight?: number): Promise<{
        hex: string;
        utxos: GetAddressUtxosResponse["result"];
        identity: Identity;
        deltas: Map<string, BigNumber>;
    }>;
    createRecoverIdentityTransaction(_identity: Identity, changeAddress: string, rawIdentityTransaction: string, identityTransactionHeight: number, utxoList?: GetAddressUtxosResponse["result"], chainIAddr?: string, fee?: number, fundRawTransactionResult?: FundRawTransactionResponse["result"], currentHeight?: number): Promise<{
        hex: string;
        utxos: GetAddressUtxosResponse["result"];
        identity: Identity;
        deltas: Map<string, BigNumber>;
    }>;
    /**
     *
     * @param unsignedTxHex The unsigned transaction hex
     * @param inputs A list of UTXOs that are being used as inputs for the transaction, in the order they appear in the unsigned tx
     * @param keys A list of WIF keys that correspond to the UTXOs in the inputs list, each utxo will be signed with each key in the list at the position of the utxo in the inputs list
     */
    signUpdateIdentityTransaction(unsignedTxHex: string, inputs: GetAddressUtxosResponse["result"], keys: string[][]): string;
}
export default VerusIdInterface;
