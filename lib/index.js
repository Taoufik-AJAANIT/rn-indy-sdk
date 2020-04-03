/**
 * Copyright 2019 ABSA Group Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
import { NativeModules } from 'react-native';
const {
  IndySdk
} = NativeModules;
export default {
  // wallet
  createWallet(config, credentials) {
    return IndySdk.createWallet(JSON.stringify(config), JSON.stringify(credentials));
  },

  openWallet(config, credentials) {
    return IndySdk.openWallet(JSON.stringify(config), JSON.stringify(credentials));
  },

  closeWallet(wh) {
    if (Platform.OS === 'ios') {
      return IndySdk.closeWallet(wh.callSomething());
    }

    return IndySdk.closeWallet(wh);
  },

  deleteWallet(config, credentials) {
    return IndySdk.deleteWallet(JSON.stringify(config), JSON.stringify(credentials));
  },

  // did

  /**
   * Value of passed `wh` parameter will be ignored in Android version of Indy native bridge,
   * because it keeps wallet as a private attribute.
   */
  createAndStoreMyDid(wh, did) {
    if (Platform.OS === 'ios') {
      return IndySdk.createAndStoreMyDid(JSON.stringify(did), wh);
    }

    return IndySdk.createAndStoreMyDid(wh, JSON.stringify(did));
  },

  keyForDid(poolHandle, wh, did) {
    if (Platform.OS === 'ios') {
      return IndySdk.keyForDid(did, poolHandle, wh);
    }

    return IndySdk.keyForDid(poolHandle, wh, did);
  },

  keyForLocalDid(wh, did) {
    if (Platform.OS === 'ios') {
      return IndySdk.keyForLocalDid(did, wh);
    }

    return IndySdk.keyForLocalDid(wh, did);
  },

  storeTheirDid(wh, identity) {
    if (Platform.OS === 'ios') {
      return IndySdk.storeTheirDid(JSON.stringify(identity), wh);
    }

    throw new Error(`Unsupported operation! Platform: ${Platform.OS}`);
  },

  // pairwise
  createPairwise(wh, theirDid, myDid, metadata = '') {
    if (Platform.OS === 'ios') {
      return IndySdk.createPairwise(theirDid, myDid, metadata, wh);
    }

    return IndySdk.createPairwise(wh, theirDid, myDid, metadata);
  },

  async getPairwise(wh, theirDid) {
    if (Platform.OS === 'ios') {
      return JSON.parse((await IndySdk.getPairwise(theirDid, wh)));
    }

    return JSON.parse((await IndySdk.getPairwise(wh, theirDid)));
  },

  // crypto
  async cryptoAnonCrypt(recipientVk, messageRaw) {
    if (Platform.OS === 'ios') {
      return IndySdk.cryptoAnonCrypt(messageRaw, recipientVk);
    }

    return Buffer.from((await IndySdk.cryptoAnonCrypt(recipientVk, Array.from(messageRaw))));
  },

  async cryptoAnonDecrypt(wh, recipientVk, encryptedMsg) {
    if (Platform.OS === 'ios') {
      return IndySdk.cryptoAnonDecrypt(encryptedMsg, recipientVk, wh);
    }

    return Buffer.from((await IndySdk.cryptoAnonDecrypt(wh, recipientVk, Array.from(encryptedMsg))));
  },

  async cryptoAuthCrypt(wh, senderVk, recipientVk, messageRaw) {
    if (Platform.OS === 'ios') {
      return IndySdk.cryptoAuthCrypt(messageRaw, senderVk, recipientVk, wh);
    }

    return Buffer.from((await IndySdk.cryptoAuthCrypt(wh, senderVk, recipientVk, Array.from(messageRaw))));
  },

  async cryptoAuthDecrypt(wh, recipientVk, encryptedMsgRaw) {
    if (Platform.OS === 'ios') {
      return IndySdk.cryptoAuthDecrypt(encryptedMsgRaw, recipientVk, wh);
    }

    const [verkey, msg] = await IndySdk.cryptoAuthDecrypt(recipientVk, Array.from(encryptedMsgRaw));
    return [verkey, Buffer.from(msg)];
  },

  async cryptoSign(wh, signerVk, message) {
    if (Platform.OS == 'ios') {
      throw new Error(`Unsupported operation! Platform: ${Platform.OS}`);
    }

    return Buffer.from((await IndySdk.cryptoSign(wh, signerVk, Array.from(message))));
  },

  cryptoVerify(signerVk, message, signature) {
    if (Platform.OS == 'ios') {
      throw new Error(`Unsupported operation! Platform: ${Platform.OS}`);
    }

    return IndySdk.cryptoVerify(signerVk, Array.from(message), Array.from(signature));
  },

  async packMessage(wh, message, receiverKeys, senderVk) {
    if (Platform.OS == 'ios') {
      throw new Error(`Unsupported operation! Platform: ${Platform.OS}`);
    }

    return Buffer.from((await IndySdk.packMessage(wh, Array.from(message), receiverKeys, senderVk)));
  },

  async unpackMessage(wh, jwe) {
    if (Platform.OS == 'ios') {
      throw new Error(`Unsupported operation! Platform: ${Platform.OS}`);
    }

    return Buffer.from((await IndySdk.unpackMessage(wh, Array.from(jwe))));
  },

  // pool
  createPoolLedgerConfig(poolName, poolConfig) {
    return IndySdk.createPoolLedgerConfig(poolName, poolConfig);
  },

  openPoolLedger(poolName, poolConfig) {
    if (Platform.OS === 'ios') {
      return IndySdk.openLedger(poolName, poolConfig);
    }

    return IndySdk.openPoolLedger(poolName, poolConfig);
  },

  setProtocolVersion(protocolVersion) {
    return IndySdk.setProtocolVersion(protocolVersion);
  },

  closePoolLedger(ph) {
    return IndySdk.closePoolLedger(ph);
  },

  async submitRequest(poolHandle, request) {
    if (Platform.OS === 'ios') {
      return JSON.parse((await IndySdk.submitRequest(request, poolHandle)));
    }

    return JSON.parse((await IndySdk.submitRequest(poolHandle, JSON.stringify(request))));
  },

  async buildGetSchemaRequest(submitterDid, id) {
    if (Platform.OS === 'ios') {
      return IndySdk.buildGetSchemaRequest(submitterDid, id);
    }

    return JSON.parse((await IndySdk.buildGetSchemaRequest(submitterDid, id)));
  },

  async parseGetSchemaResponse(getSchemaResponse) {
    if (Platform.OS === 'ios') {
      return IndySdk.parseGetSchemaResponse(JSON.stringify(getSchemaResponse));
    }

    const [id, schema] = await IndySdk.parseGetSchemaResponse(JSON.stringify(getSchemaResponse));
    return [id, JSON.parse(schema)];
  },

  async buildGetCredDefRequest(submitterDid, id) {
    if (Platform.OS === 'ios') {
      return IndySdk.buildGetCredDefRequest(submitterDid, id);
    }

    return JSON.parse((await IndySdk.buildGetCredDefRequest(submitterDid, id)));
  },

  async parseGetCredDefResponse(getCredDefResponse) {
    if (Platform.OS === 'ios') {
      return IndySdk.parseGetCredDefResponse(JSON.stringify(getCredDefResponse));
    }

    const [credDefId, credDef] = await IndySdk.parseGetCredDefResponse(JSON.stringify(getCredDefResponse));
    return [credDefId, JSON.parse(credDef)];
  },

  proverCreateMasterSecret(wh, masterSecretId) {
    if (Platform.OS === 'ios') {
      return IndySdk.proverCreateMasterSecret(masterSecretId, wh);
    }

    return IndySdk.proverCreateMasterSecret(wh, masterSecretId);
  },

  async proverCreateCredentialReq(wh, proverDid, credOffer, credDef, masterSecretId) {
    if (Platform.OS === 'ios') {
      return IndySdk.proverCreateCredentialReq(JSON.stringify(credOffer), JSON.stringify(credDef), proverDid, masterSecretId, wh);
    }

    const [credReq, credReqMetadata] = await IndySdk.proverCreateCredentialReq(wh, proverDid, JSON.stringify(credOffer), JSON.stringify(credDef), masterSecretId);
    return [JSON.parse(credReq), JSON.parse(credReqMetadata)];
  },

  proverStoreCredential(wh, credId, credReqMetadata, cred, credDef, revRegDef) {
    if (Platform.OS === 'ios') {
      return IndySdk.proverStoreCredential(JSON.stringify(cred), credId, JSON.stringify(credReqMetadata), JSON.stringify(credDef), revRegDef && JSON.stringify(revRegDef), wh);
    }

    return IndySdk.proverStoreCredential(wh, credId, JSON.stringify(credReqMetadata), JSON.stringify(cred), JSON.stringify(credDef), revRegDef && JSON.stringify(revRegDef));
  },

  async proverGetCredentials(wh, filter = {}) {
    if (Platform.OS === 'ios') {
      return JSON.parse((await IndySdk.proverGetCredentials(JSON.stringify(filter), wh)));
    }

    return JSON.parse((await IndySdk.proverGetCredentials(wh, JSON.stringify(filter))));
  },

  async proverGetCredential(wh, credId) {
    if (Platform.OS === 'ios') {
      return JSON.parse((await IndySdk.proverGetCredential(credId, wh)));
    }

    return JSON.parse((await IndySdk.proverGetCredential(wh, credId)));
  },

  // TODO Add return flow type.
  // It needs little investigation, because is doesn't seem to be same format as Credential stored in wallet.
  async proverGetCredentialsForProofReq(wh, proofRequest) {
    if (Platform.OS == 'ios') {
      return JSON.parse((await IndySdk.proverGetCredentialsForProofReq(JSON.stringify(proofRequest), wh)));
    }

    return JSON.parse((await IndySdk.proverGetCredentialsForProofReq(wh, JSON.stringify(proofRequest))));
  },

  async proverCreateProof(wh, proofReq, requestedCredentials, masterSecretName, schemas, credentialDefs, revStates = {}) {
    if (Platform.OS == 'ios') {
      return JSON.parse((await IndySdk.proverCreateProofForRequest(JSON.stringify(proofReq), JSON.stringify(requestedCredentials), masterSecretName, JSON.stringify(schemas), JSON.stringify(credentialDefs), JSON.stringify(revStates), wh)));
    }

    return JSON.parse((await IndySdk.proverCreateProof(
      wh,
      JSON.stringify(proofReq),
      JSON.stringify(requestedCredentials),
      masterSecretName,
      JSON.stringify(schemas),
      JSON.stringify(credentialDefs),
      JSON.stringify(revStates)
    )));
  },

  // non_secrets
  async addWalletRecord(wh, type, id, value, tags) {
    if (Platform.OS == 'ios') {
      throw new Error(`Unsupported platform! ${Platform.OS}`);
    }

    return IndySdk.addWalletRecord(wh, type, id, value, JSON.stringify(tags));
  },

  async updateWalletRecordValue(wh, type, id, value) {
    if (Platform.OS == 'ios') {
      throw new Error(`Unsupported platform! ${Platform.OS}`);
    }

    return IndySdk.updateWalletRecordValue(wh, type, id, value);
  },

  async updateWalletRecordTags(wh, type, id, tags) {
    if (Platform.OS == 'ios') {
      throw new Error(`Unsupported platform! ${Platform.OS}`);
    }

    return IndySdk.updateWalletRecordTags(wh, type, id, JSON.stringify(tags));
  },

  async addWalletRecordTags(wh, type, id, tags) {
    if (Platform.OS == 'ios') {
      throw new Error(`Unsupported platform! ${Platform.OS}`);
    }

    return IndySdk.addWalletRecordTags(wh, type, id, JSON.stringify(tags));
  },

  async deleteWalletRecordTags(wh, type, id, tagNames) {
    if (Platform.OS == 'ios') {
      throw new Error(`Unsupported platform! ${Platform.OS}`);
    }

    return IndySdk.deleteWalletRecordTags(wh, type, id, JSON.stringify(tagNames));
  },

  async deleteWalletRecord(wh, type, id) {
    if (Platform.OS == 'ios') {
      throw new Error(`Unsupported platform! ${Platform.OS}`);
    }

    return IndySdk.deleteWalletRecord(wh, type, id);
  },

  async getWalletRecord(wh, type, id, options) {
    if (Platform.OS == 'ios') {
      throw new Error(`Unsupported platform! ${Platform.OS}`);
    }

    return JSON.parse((await IndySdk.getWalletRecord(wh, type, id, options)));
  },

  async openWalletSearch(wh, type, query, options) {
    if (Platform.OS == 'ios') {
      throw new Error(`Unsupported platform! ${Platform.OS}`);
    }

    console.log('wh, type, query :', wh, type, query);
    return IndySdk.openWalletSearch(wh, type, JSON.stringify(query), JSON.stringify(options));
  },

  async fetchWalletSearchNextRecords(wh, sh, count) {
    if (Platform.OS == 'ios') {
      throw new Error(`Unsupported platform! ${Platform.OS}`);
    }

    return JSON.parse((await IndySdk.fetchWalletSearchNextRecords(wh, sh, count)));
  },

  async closeWalletSearch(sh) {
    if (Platform.OS == 'ios') {
      throw new Error(`Unsupported platform! ${Platform.OS}`);
    }

    return IndySdk.closeWalletSearch(sh);
  }

};

