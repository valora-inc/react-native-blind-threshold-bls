declare namespace BlindThresholdBls {
  function blindMessage(message: string): Promise<string>;
  function blindMessageWithRandom(message: string, random: string): Promise<string>;
  function unblindMessage(
    base64BlindedSignature: string,
    base64SignerPublicKey: string
  ): Promise<string>;
}

export default BlindThresholdBls;
