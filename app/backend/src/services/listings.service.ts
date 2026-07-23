interface QueryFilters {
  search?: string;
  sort: string;
  page: number;
  limit: number;
  minPrice?: number;
  maxPrice?: number;
  status: string;
}

export class ListingsService {
  static async queryListings(filters: QueryFilters) {
    const mockListings = [
      {
        id: 'list_1',
        title: 'Exclusive Username Credit',
        username: 'quickex.to/alice',
        price: 50.0,
        status: 'active',
        createdAt: new Date().toISOString(),
        endingSoon: false,
        bidSummary: { totalBids: 3, highestBid: 45.0 },
      },
    ];

    return {
      listings: mockListings,
      total: mockListings.length,
    };
  }
}
