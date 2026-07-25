import {
  Controller,
  Post,
  Get,
  Body,
  Param,
  HttpCode,
  HttpStatus,
  Request,
  NotFoundException,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { ReportIssueService } from './report-issue.service';
import { CreateReportIssueDto, ReportIssueDto } from './dto';
import { ReportIssueResponseDto } from './dto/report-issue-response.dto';

/**
 * Controller for issue report submission and retrieval
 */
@ApiTags('report-issue')
@Controller('report-issue')
export class ReportIssueController {
  constructor(private readonly reportIssueService: ReportIssueService) {}

  /**
   * Submit a new issue report
   */
  @Post()
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Submit a new issue report' })
  @ApiResponse({
    status: 201,
    description: 'Issue report submitted successfully',
    type: ReportIssueResponseDto,
  })
  @ApiResponse({ status: 400, description: 'Invalid request or abuse limit exceeded' })
  @ApiResponse({ status: 429, description: 'Rate limit exceeded' })
  async submitReport(
    @Body() dto: CreateReportIssueDto,
    @Request() req: Request,
  ): Promise<ReportIssueResponseDto> {
    // Extract IP address from request
    const ipAddress = this.extractIpAddress(req);
    
    const reportId = await this.reportIssueService.submitReport(
      {
        userId: dto.userId,
        issueType: dto.issueType,
        title: dto.title,
        description: dto.description,
        environment: dto.environment,
        reproduction: dto.reproduction,
        context: dto.context,
        attachments: dto.attachments,
      },
      ipAddress,
    );
    
    return {
      id: reportId,
      message: 'Issue report submitted successfully',
    };
  }

  /**
   * Get issue reports for a specific user
   */
  @Get('user/:userId')
  @ApiOperation({ summary: 'Get issue reports for a user' })
  @ApiResponse({
    status: 200,
    description: 'Issue reports retrieved successfully',
    type: [ReportIssueDto],
  })
  async getUserReports(
    @Param('userId') userId: string,
  ): Promise<ReportIssueDto[]> {
    const reports = await this.reportIssueService.getReportsByUser(userId);
    
    return reports.map(report => this.mapToDto(report));
  }

  /**
   * Get all issue reports (admin only)
   */
  @Get('admin/all')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get all issue reports (admin only)' })
  @ApiResponse({
    status: 200,
    description: 'All issue reports retrieved successfully',
    type: [ReportIssueDto],
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Forbidden - admin access required' })
  async getAllReports(
    @Request() req: Request,
  ): Promise<ReportIssueDto[]> {
    // TODO: Add admin role check when auth is properly integrated
    // For now, this endpoint is available but should be protected
    
    const limit = 50;
    const offset = 0;
    
    const reports = await this.reportIssueService.getAllReports(limit, offset);
    return reports.map(report => this.mapToDto(report));
  }

  /**
   * Get a specific issue report by ID
   */
  @Get(':reportId')
  @ApiOperation({ summary: 'Get a specific issue report by ID' })
  @ApiResponse({
    status: 200,
    description: 'Issue report retrieved successfully',
    type: ReportIssueDto,
  })
  @ApiResponse({ status: 404, description: 'Report not found' })
  async getReport(@Param('reportId') reportId: string): Promise<ReportIssueDto> {
    const report = await this.reportIssueService.getReportById(reportId);
    
    if (!report) {
      throw new NotFoundException('Issue report not found');
    }
    
    return this.mapToDto(report);
  }

  /**
   * Extract IP address from request
   */
  private extractIpAddress(req: Request): string {
    const request = req as any;
    
    // Check for forwarded IP (behind proxy/load balancer)
    const forwardedFor = request.headers?.['x-forwarded-for'];
    if (typeof forwardedFor === 'string' && forwardedFor.length > 0) {
      return forwardedFor.split(',')[0].trim();
    }
    
    // Fall back to direct IP
    return request.ip || 'unknown';
  }

  /**
   * Map ReportIssue entity to ReportIssueDto
   */
  private mapToDto(report: any): ReportIssueDto {
    return {
      id: report.id,
      userId: report.userId,
      issueType: report.issueType,
      title: report.title,
      description: report.description,
      environment: report.environment,
      reproduction: report.reproduction,
      context: report.context,
      attachments: report.attachments,
      redactedPayload: report.redactedPayload,
      createdAt: report.createdAt,
    };
  }
}
