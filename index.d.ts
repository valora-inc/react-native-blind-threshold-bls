declare namespace BlindThresholdBls {
  function blindMessage(message: string): Promise<string>;
  function unblindMessage(base64BlindedSignature: string): Promise<string>;
}

export default BlindThresholdBls;
