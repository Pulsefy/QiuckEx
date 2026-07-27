import {
  Controller,
  Get,
  Put,
  Body,
  Param,
  HttpCode,
  HttpStatus,
  NotFoundException,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { CrashReportingService } from './crash-reporting.service';
import { UpdateSettingsDto } from './dto/update-settings.dto';
import { CrashReportDto } from './dto/crash-report.dto';
import { LogExportDto } from './dto/log-export.dto';
import { SettingsDto } from './dto/settings.dto';

/**
 * Controller for crash reporting and log export endpoints
 */
@ApiTags('crash-reporting')
@Controller('crash-reporting')
export class CrashReportingController {
  constructor(private readonly crashReportingService: CrashReportingService) {}

  /**
   * Get user's crash reporting settings
   */
  @Get('settings/:userId')
  @ApiOperation({ summary: 'Get crash reporting settings for a user' })
  @ApiResponse({
    status: 200,
    description: 'Settings retrieved successfully',
    type: SettingsDto,
  })
  @ApiResponse({ status: 404, description: 'Settings not found' })
  async getSettings(@Param('userId') userId: string): Promise<SettingsDto> {
    const settings = await this.crashReportingService.getUserSettings(userId);
    
    if (!settings) {
      // Return default settings if not found
      return {
        userId,
        crashReportingEnabled: false,
        updatedAt: new Date(),
      };
    }

    return {
      userId: settings.userId,
      crashReportingEnabled: settings.crashReportingEnabled,
      updatedAt: settings.updatedAt,
    };
  }

  /**
   * Update user's crash reporting settings
   */
  @Put('settings/:userId')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Update crash reporting settings for a user' })
  @ApiResponse({ status: 200, description: 'Settings updated successfully' })
  async updateSettings(
    @Param('userId') userId: string,
    @Body() dto: UpdateSettingsDto,
  ): Promise<{ message: string }> {
    await this.crashReportingService.updateUserSettings(userId, dto.enabled);
    
    return {
      message: `Crash reporting ${dto.enabled ? 'enabled' : 'disabled'} successfully`,
    };
  }

  /**
   * Export logs for support (requires opt-in)
   */
  @Get('export/:userId')
  @ApiOperation({ summary: 'Export logs for support' })
  @ApiResponse({
    status: 200,
    description: 'Logs exported successfully',
    type: LogExportDto,
  })
  @ApiResponse({
    status: 404,
    description: 'User has not opted in to crash reporting',
  })
  async exportLogs(@Param('userId') userId: string): Promise<LogExportDto> {
    const logExport = await this.crashReportingService.exportLogs(userId);
    
    if (!logExport) {
      throw new NotFoundException(
        'User has not opted in to crash reporting or logs are not available',
      );
    }

    return {
      userId: logExport.userId,
      exportedAt: logExport.exportedAt,
      currentLogs: logExport.currentLogs,
      crashReports: logExport.crashReports,
    };
  }

  /**
   * Get crash reports for a user
   */
  @Get('reports/:userId')
  @ApiOperation({ summary: 'Get crash reports for a user' })
  @ApiResponse({
    status: 200,
    description: 'Crash reports retrieved successfully',
    type: [CrashReportDto],
  })
  async getCrashReports(
    @Param('userId') userId: string,
  ): Promise<CrashReportDto[]> {
    const reports = await this.crashReportingService.getCrashReports(userId);
    
    return reports.map(report => ({
      id: report.id,
      userId: report.userId,
      error: report.error,
      context: report.context,
      logLines: report.logLines,
      timestamp: report.timestamp,
      createdAt: report.createdAt,
    }));
  }
}
