function blindMessage(message: string): Promise<string>;

function unblindMessage(base64BlindedSignature: string): Promise<string>;

const BlindThresholdBls = {
  blindMessage,
  unblindMessage,
};

export default BlindThresholdBls;
