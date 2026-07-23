import { Request, Response } from 'express';
import { ListingsService } from '../services/listings.service';

export class ListingsController {
  static async getListings(req: Request, res: Response) {
    try {
      const {
        search,
        sort = 'newest',
        page = '1',
        limit = '10',
        minPrice,
        maxPrice,
        status = 'active',
      } = req.query;

      const filters = {
        search: search as string,
        sort: sort as string,
        page: parseInt(page as string, 10),
        limit: parseInt(limit as string, 10),
        minPrice: minPrice ? parseFloat(minPrice as string) : undefined,
        maxPrice: maxPrice ? parseFloat(maxPrice as string) : undefined,
        status: status as string,
      };

      const result = await ListingsService.queryListings(filters);
      return res.status(200).json({
        success: true,
        data: result.listings,
        pagination: {
          total: result.total,
          page: filters.page,
          limit: filters.limit,
          pages: Math.ceil(result.total / filters.limit),
        },
      });
    } catch (error: any) {
      return res.status(500).json({ success: false, error: error.message });
    }
  }
}
