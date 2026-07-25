import { validate } from 'class-validator';
import { plainToInstance } from 'class-transformer';
import { CreateReportIssueDto, EnvironmentInfoDto, AttachmentReferenceDto } from './';

describe('CreateReportIssueDto', () => {
  it('should validate a valid submission', async () => {
    const dto = new CreateReportIssueDto();
    dto.issueType = 'bug';
    dto.title = 'Test issue';
    dto.description = 'Test description';
    dto.environment = new EnvironmentInfoDto();
    dto.environment.platform = 'ios';
    dto.environment.appVersion = '1.0.0';

    const errors = await validate(dto);
    expect(errors).toHaveLength(0);
  });

  it('should fail validation when issueType is missing', async () => {
    const dto = new CreateReportIssueDto();
    dto.title = 'Test issue';
    dto.description = 'Test description';
    dto.environment = new EnvironmentInfoDto();

    const errors = await validate(dto);
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0].property).toBe('issueType');
  });

  it('should fail validation when title is missing', async () => {
    const dto = new CreateReportIssueDto();
    dto.issueType = 'bug';
    dto.description = 'Test description';
    dto.environment = new EnvironmentInfoDto();

    const errors = await validate(dto);
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0].property).toBe('title');
  });

  it('should fail validation when description is missing', async () => {
    const dto = new CreateReportIssueDto();
    dto.issueType = 'bug';
    dto.title = 'Test issue';
    dto.environment = new EnvironmentInfoDto();

    const errors = await validate(dto);
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0].property).toBe('description');
  });

  it('should fail validation when environment is missing', async () => {
    const dto = new CreateReportIssueDto();
    dto.issueType = 'bug';
    dto.title = 'Test issue';
    dto.description = 'Test description';

    const errors = await validate(dto);
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0].property).toBe('environment');
  });

  it('should accept valid attachments', async () => {
    const dto = plainToInstance(CreateReportIssueDto, {
      issueType: 'bug',
      title: 'Test issue',
      description: 'Test description',
      environment: {},
      attachments: [
        {
          id: 'att_1',
          name: 'screenshot.png',
          type: 'image/png',
          size: 1024,
        },
      ],
    });

    const errors = await validate(dto);
    expect(errors).toHaveLength(0);
  });

  it('should accept optional fields', async () => {
    const dto = new CreateReportIssueDto();
    dto.issueType = 'bug';
    dto.title = 'Test issue';
    dto.description = 'Test description';
    dto.environment = new EnvironmentInfoDto();
    dto.userId = 'user_123';
    dto.reproduction = 'Step 1\nStep 2';
    dto.context = { linkId: 'link_123' };

    const errors = await validate(dto);
    expect(errors).toHaveLength(0);
  });
});

describe('EnvironmentInfoDto', () => {
  it('should validate with all fields', async () => {
    const dto = new EnvironmentInfoDto();
    dto.platform = 'ios';
    dto.platformVersion = '17.0';
    dto.appVersion = '1.0.0';
    dto.userAgent = 'Mozilla/5.0...';
    dto.locale = 'en-US';
    dto.timezone = 'America/Los_Angeles';
    dto.screenWidth = 390;
    dto.screenHeight = 844;

    const errors = await validate(dto);
    expect(errors).toHaveLength(0);
  });

  it('should validate with no fields (all optional)', async () => {
    const dto = new EnvironmentInfoDto();

    const errors = await validate(dto);
    expect(errors).toHaveLength(0);
  });
});

describe('AttachmentReferenceDto', () => {
  it('should validate a valid attachment', async () => {
    const dto = new AttachmentReferenceDto();
    dto.id = 'att_1';
    dto.name = 'screenshot.png';
    dto.type = 'image/png';
    dto.size = 1024;

    const errors = await validate(dto);
    expect(errors).toHaveLength(0);
  });

  it('should fail validation when id is missing', async () => {
    const dto = new AttachmentReferenceDto();
    dto.name = 'screenshot.png';
    dto.type = 'image/png';
    dto.size = 1024;

    const errors = await validate(dto);
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0].property).toBe('id');
  });

  it('should fail validation when name is missing', async () => {
    const dto = new AttachmentReferenceDto();
    dto.id = 'att_1';
    dto.type = 'image/png';
    dto.size = 1024;

    const errors = await validate(dto);
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0].property).toBe('name');
  });

  it('should fail validation when type is missing', async () => {
    const dto = new AttachmentReferenceDto();
    dto.id = 'att_1';
    dto.name = 'screenshot.png';
    dto.size = 1024;

    const errors = await validate(dto);
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0].property).toBe('type');
  });

  it('should fail validation when size is missing', async () => {
    const dto = new AttachmentReferenceDto();
    dto.id = 'att_1';
    dto.name = 'screenshot.png';
    dto.type = 'image/png';

    const errors = await validate(dto);
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0].property).toBe('size');
  });

  it('should accept optional url field', async () => {
    const dto = new AttachmentReferenceDto();
    dto.id = 'att_1';
    dto.name = 'screenshot.png';
    dto.type = 'image/png';
    dto.size = 1024;
    dto.url = 'https://example.com/attachment.png';

    const errors = await validate(dto);
    expect(errors).toHaveLength(0);
  });
});
