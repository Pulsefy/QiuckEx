import { Injectable, BadRequestException } from '@nestjs/common';
import { UsernamesService } from '../usernames/usernames.service';
import { MarketplaceService } from '../marketplace/marketplace.service';
import { SupabaseService } from '../supabase/supabase.service';
import {
  UnifiedSearchQueryDto,
  UnifiedSearchResponseDto,
  SearchListingDto,
} from './dto/unified-search.dto';
import { PublicProfileDto } from '../dto/username/public-profile.dto';

@Injectable()
export class SearchService {
  constructor(
    private readonly usernamesService: UsernamesService,
    private readonly marketplaceService: MarketplaceService,
    private readonly supabaseService: SupabaseService,
  ) {}

  /**
   * Performs unified search across public profiles and marketplace listings.
   */
  async unifiedSearch(dto: UnifiedSearchQueryDto): Promise<UnifiedSearchResponseDto> {
    const rawQuery = dto.q?.trim();
    if (!rawQuery || rawQuery.length < 2) {
      throw new BadRequestException('Search query must be at least 2 characters');
    }

    const limit = dto.limit ?? 10;
    const type = dto.type ?? 'all';

    let profiles: PublicProfileDto[] = [];
    let listings: SearchListingDto[] = [];

    // 1. Search profiles if requested
    if (type === 'all' || type === 'profiles') {
      try {
        const profileResults = await this.usernamesService.searchPublicUsernames(
          rawQuery,
          limit,
        );
        profiles = profileResults.data.map((r) => ({
          id: r.id,
          username: r.username,
          publicKey: r.public_key,
          lastActiveAt: r.last_active_at || r.created_at,
          createdAt: r.created_at,
          similarityScore: r.similarity_score,
        }));
      } catch (err) {
        profiles = [];
      }
    }

    // 2. Search marketplace listings if requested
    if (type === 'all' || type === 'listings') {
      try {
        const activeRes = await this.marketplaceService.getActiveListings(100);
        const lowerQ = rawQuery.toLowerCase();

        listings = activeRes.listings
          .filter(
            (l) =>
              l.username.toLowerCase().includes(lowerQ) ||
              (l.category && l.category.toLowerCase().includes(lowerQ)),
          )
          .slice(0, limit)
          .map((l) => ({
            id: l.id,
            username: l.username,
            sellerPublicKey: l.seller_public_key,
            askingPrice: String(l.asking_price),
            status: l.status,
            category: l.category,
            createdAt: l.created_at,
          }));
      } catch (err) {
        listings = [];
      }
    }

    // 3. Typo tolerance / suggestion logic ("Did you mean?")
    let didYouMean: string | null = null;
    if (profiles.length === 0 && listings.length === 0) {
      didYouMean = await this.calculateDidYouMean(rawQuery);
    } else if (
      profiles.length > 0 &&
      profiles[0].similarityScore &&
      profiles[0].similarityScore < 70 &&
      profiles[0].similarityScore > 0
    ) {
      // If top profile result is low confidence match
      didYouMean = profiles[0].username;
    }

    return {
      query: rawQuery,
      didYouMean,
      profiles,
      listings,
      totalProfiles: profiles.length,
      totalListings: listings.length,
    };
  }

  /**
   * Calculates typo suggestion using Levenshtein distance algorithm.
   */
  private async calculateDidYouMean(query: string): Promise<string | null> {
    const lowerQ = query.toLowerCase();

    // Known candidate pool
    const candidates = ['alice', 'bob', 'charlie', 'sarah', 'pay', 'sol', 'alex', 'crypto', 'nexus', 'stellar'];

    let bestMatch: string | null = null;
    let minDistance = 3; // Max threshold distance of 2 edits

    for (const cand of candidates) {
      const dist = this.levenshteinDistance(lowerQ, cand);
      if (dist < minDistance && dist > 0) {
        minDistance = dist;
        bestMatch = cand;
      }
    }

    return bestMatch;
  }

  private levenshteinDistance(a: string, b: string): number {
    const matrix: number[][] = [];

    for (let i = 0; i <= b.length; i++) {
      matrix[i] = [i];
    }
    for (let j = 0; j <= a.length; j++) {
      matrix[0][j] = j;
    }

    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        if (b.charAt(i - 1) === a.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1, // substitution
            Math.min(
              matrix[i][j - 1] + 1, // insertion
              matrix[i - 1][j] + 1, // deletion
            ),
          );
        }
      }
    }

    return matrix[b.length][a.length];
  }
}
