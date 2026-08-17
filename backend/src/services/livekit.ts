import { AccessToken, RoomServiceClient } from 'livekit-server-sdk';
import { logger } from '../logger.js';
import dotenv from 'dotenv';

dotenv.config();

const apiKey = process.env.LIVEKIT_API_KEY || 'devkey';
const apiSecret = process.env.LIVEKIT_API_SECRET || 'secret';
const livekitHost = process.env.LIVEKIT_HOST || 'http://localhost:7880';

export const roomServiceClient = new RoomServiceClient(livekitHost, apiKey, apiSecret);

export const INTERCOM_ROOM_NAME = 'mobile-ic-main';

export interface GenerateTokenOptions {
  identity: string;
  name: string;
  panelCode: string;
  metadata?: string;
}

export const generateLiveKitToken = async (options: GenerateTokenOptions): Promise<string> => {
  const at = new AccessToken(apiKey, apiSecret, {
    identity: options.identity,
    name: options.name,
    metadata: options.metadata,
  });

  at.addGrant({
    roomJoin: true,
    room: INTERCOM_ROOM_NAME,
    canPublish: true,
    canSubscribe: true,
    canPublishData: true,
  });

  return await at.toJwt();
};

/**
 * Dynamically updates participant permissions and metadata in the active LiveKit room
 */
export const updateLiveKitParticipantPermissions = async (
  panelId: string,
  metadata: string
) => {
  try {
    // Update participant metadata so clients are instantly notified via LiveKit SDK event
    await roomServiceClient.updateParticipant(INTERCOM_ROOM_NAME, panelId, metadata, {
      canPublish: true,
      canSubscribe: true,
      canPublishData: true,
    });
    logger.info({ panelId }, 'Successfully updated LiveKit participant metadata');
  } catch (err: any) {
    // Participant might not be currently connected to room; log info rather than error
    logger.info({ panelId, message: err.message }, 'Participant not currently active in LiveKit room during update');
  }
};
