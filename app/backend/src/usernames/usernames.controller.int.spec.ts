import { Test, TestingModule } from '@nestjs/testing';
import { ConflictException, ForbiddenException } from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { UsernamesController } from './usernames.controller';
import { UsernamesService } from './usernames.service';
import {
  UsernameConflictError,
  UsernameLimitExceededError,
} from './errors';

describe('UsernamesController', () => {
  let controller: UsernamesController;
  let usernamesService: jest.Mocked<UsernamesService>;
  let eventEmitter: jest.Mocked<EventEmitter2>;

  const validPublicKey = 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR';

  beforeEach(async () => {
    const mockCreate = jest.fn().mockResolvedValue({ ok: true });
    const mockListByPublicKey = jest.fn().mockResolvedValue([]);
    const mockEmit = jest.fn();

    const module: TestingModule = await Test.createTestingModule({
      controllers: [UsernamesController],
      providers: [
        {
          provide: UsernamesService,
          useValue: {
            create: mockCreate,
            listByPublicKey: mockListByPublicKey,
          },
        },
        {
          provide: EventEmitter2,
          useValue: { emit: mockEmit },
        },
      ],
    }).compile();

    controller = module.get<UsernamesController>(UsernamesController);
    usernamesService = module.get(UsernamesService) as jest.Mocked<UsernamesService>;
    eventEmitter = module.get(EventEmitter2) as jest.Mocked<EventEmitter2>;
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('createUsername', () => {
    it('returns 201 and ok: true on success', async () => {
      const body = { username: 'alice_123', publicKey: validPublicKey };
      const result = await controller.createUsername(body);
      expect(result).toEqual({ ok: true });
      expect(usernamesService.create).toHaveBeenCalledWith('alice_123', validPublicKey);
      expect(eventEmitter.emit).toHaveBeenCalledWith(
        'username.claimed',
        expect.objectContaining({
          username: 'alice_123',
          publicKey: validPublicKey,
        }),
      );
    });

    it('throws ConflictException when username is already taken', async () => {
      usernamesService.create.mockRejectedValueOnce(
        new UsernameConflictError('taken'),
      );
      const body = { username: 'taken', publicKey: validPublicKey };
      const err = await controller.createUsername(body).catch((e) => e);
      expect(err).toBeInstanceOf(ConflictException);
      expect(err.response).toMatchObject({
        code: 'USERNAME_CONFLICT',
        message: expect.stringContaining('taken'),
      });
    });

    it('throws ForbiddenException when wallet limit exceeded', async () => {
      usernamesService.create.mockRejectedValueOnce(
        new UsernameLimitExceededError(validPublicKey, 2),
      );
      const body = { username: 'newuser', publicKey: validPublicKey };
      const err = await controller.createUsername(body).catch((e) => e);
      expect(err).toBeInstanceOf(ForbiddenException);
      expect(err.response).toMatchObject({ code: 'USERNAME_LIMIT_EXCEEDED' });
    });
  });

  describe('listUsernames', () => {
    it('returns usernames for wallet', async () => {
      const rows = [
        {
          id: 'id1',
          username: 'alice',
          public_key: validPublicKey,
          created_at: '2025-01-01T00:00:00Z',
        },
      ];
      usernamesService.listByPublicKey.mockResolvedValueOnce(rows);
      const result = await controller.listUsernames({ publicKey: validPublicKey });
      expect(result).toEqual({ usernames: rows });
      expect(usernamesService.listByPublicKey).toHaveBeenCalledWith(validPublicKey);
    });
  });
});
