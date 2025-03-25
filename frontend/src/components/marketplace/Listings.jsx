/**
 * Listings Component
 * 
 * A comprehensive interface for browsing, filtering, and interacting with
 * data vault listings in the PrivaSight marketplace.
 */

import React, { useState, useEffect, useMemo } from 'react';
import PropTypes from 'prop-types';
import { useDataVault } from '../../hooks/useDataVault';
import { usePrivacyLayer } from '../../hooks/usePrivacyLayer';
import { usePrivaToken } from '../../hooks/usePrivaToken';

// Icons (Assuming these are imported from a custom icon library)
import {
  Search, Filter, Grid, List, ChevronDown, Star, StarHalf, ExternalLink,
  Database, Shield, Users, Eye, EyeOff, Lock, Clock, Tag, BarChart2,
  AlertTriangle, Info, Shuffle, ChevronRight, ZeroKnowledge, Heart,
  Share, Download, X, FileText, Check, Plus, DollarSign, Sliders,
  Play, PieChart, Zap
} from '../icons';

// Common Components
import Button, { IconButton } from '../common/Button';
import Card from '../common/Card';
import Modal from '../common/Modal';

const Listings = ({
  userAddress,
  className = '',
  ...props
}) => {
  // === State Management ===
  const [listings, setListings] = useState([]);
  const [featuredListings, setFeaturedListings] = useState([]);
  const [trendingListings, setTrendingListings] = useState([]);
  const [categories, setCategories] = useState([]);
  const [selectedListing, setSelectedListing] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [favoriteListings, setFavoriteListings] = useState([]);

  // Search & Filter State
  const [searchTerm, setSearchTerm] = useState('');
  const [filters, setFilters] = useState({
    category: 'all',
    privacyTechnology: 'all',
    accessType: 'all',
    priceRange: 'all',
    dataSize: 'all',
    dataAge: 'all',
    rating: 0
  });
  const [sortBy, setSortBy] = useState('relevance');
  const [viewMode, setViewMode] = useState('grid');
  const [page, setPage] = useState(1);
  const [pageSize] = useState(12);
  const [showAdvancedFilters, setShowAdvancedFilters] = useState(false);

  // Modal States
  const [showDetailModal, setShowDetailModal] = useState(false);
  const [showSampleDataModal, setShowSampleDataModal] = useState(false);
  const [showAccessRequestModal, setShowAccessRequestModal] = useState(false);

  // === Custom Hooks ===
  const { 
    getMarketplaceListings, getFeaturedListings, getTrendingListings,
    getListingCategories, getListingDetails, getSampleData, getUserFavorites,
    toggleFavorite, requestAccess, purchaseDataset 
  } = useDataVault();

  const { getPrivacyMetrics, verifyPrivacyProtections } = usePrivacyLayer();
  const { getTokenBalance, getDatasetPrice, estimateTransactionFees } = usePrivaToken();

  // === Effects ===
  // Load initial marketplace data
  useEffect(() => {
    const loadMarketplaceData = async () => {
      try {
        setIsLoading(true);
        const listingsData = await getMarketplaceListings({ search: searchTerm, filters, sort: sortBy, page, pageSize });
        const featured = await getFeaturedListings();
        const trending = await getTrendingListings();
        const categoriesData = await getListingCategories();

        setListings(listingsData.listings);
        setFeaturedListings(featured);
        setTrendingListings(trending);
        setCategories(categoriesData);
        setError(null);
      } catch (err) {
        console.error('Failed to load marketplace data:', err);
        setError('Failed to load marketplace listings. Please try again later.');
      } finally {
        setIsLoading(false);
      }
    };
    loadMarketplaceData();
  }, [searchTerm, filters, sortBy, page, getMarketplaceListings, getFeaturedListings, getTrendingListings, getListingCategories]);

  // Load user favorites if logged in
  useEffect(() => {
    const loadUserFavorites = async () => {
      if (!userAddress) return;
      try {
        const favorites = await getUserFavorites(userAddress);
        setFavoriteListings(favorites.map(f => f.id));
      } catch (err) {
        console.error('Failed to load user favorites:', err);
      }
    };
    loadUserFavorites();
  }, [userAddress, getUserFavorites]);

  // Load detailed listing info when selected
  useEffect(() => {
    const loadListingDetails = async () => {
      if (!selectedListing || !showDetailModal) return;
      try {
        setIsLoading(true);
        const details = await getListingDetails(selectedListing.id);
        setSelectedListing({ ...selectedListing, ...details });
        setError(null);
      } catch (err) {
        console.error('Failed to load listing details:', err);
        setError('Failed to load listing details. Please try again.');
      } finally {
        setIsLoading(false);
      }
    };
    loadListingDetails();
  }, [selectedListing, showDetailModal, getListingDetails]);

  // === Derived State ===
  const totalPages = useMemo(() => Math.ceil(listings.length / pageSize) || 1, [listings.length, pageSize]);
  const currentListings = useMemo(() => {
    const start = (page - 1) * pageSize;
    return listings.slice(start, start + pageSize);
  }, [listings, page, pageSize]);

  // === Event Handlers ===
  const handleSearch = (e) => {
    setSearchTerm(e.target.value);
    setPage(1);
  };

  const handleFilterChange = (key, value) => {
    setFilters(prev => ({ ...prev, [key]: value }));
    setPage(1);
  };

  const handleSortChange = (value) => {
    setSortBy(value);
    setPage(1);
  };

  const handleListingClick = (listing) => {
    setSelectedListing(listing);
    setShowDetailModal(true);
  };

  const handleToggleFavorite = async (listingId) => {
    if (!userAddress) return;
    try {
      await toggleFavorite(userAddress, listingId);
      setFavoriteListings(prev => 
        prev.includes(listingId) ? prev.filter(id => id !== listingId) : [...prev, listingId]
      );
    } catch (err) {
      console.error('Failed to toggle favorite:', err);
    }
  };

  const handleRequestAccess = async (listingId, accessDetails) => {
    try {
      setIsLoading(true);
      const result = await requestAccess(userAddress, listingId, accessDetails);
      if (result.success && selectedListing?.id === listingId) {
        setSelectedListing({ ...selectedListing, accessRequestStatus: 'pending' });
      }
      setShowAccessRequestModal(false);
    } catch (err) {
      console.error('Failed to request access:', err);
      setError('Failed to request access. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handlePurchaseDataset = async (listingId) => {
    if (!userAddress) return;
    try {
      setIsLoading(true);
      const result = await purchaseDataset(userAddress, listingId);
      if (result.success && selectedListing?.id === listingId) {
        setSelectedListing({ ...selectedListing, hasAccess: true });
      }
    } catch (err) {
      console.error('Failed to purchase dataset:', err);
      setError('Failed to purchase dataset. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleShowSampleData = async (listingId) => {
    try {
      setIsLoading(true);
      const sampleData = await getSampleData(listingId);
      setSelectedListing(prev => ({ ...prev, sampleData }));
      setShowSampleDataModal(true);
    } catch (err) {
      console.error('Failed to load sample data:', err);
      setError('Failed to load sample data. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleClearFilters = () => {
    setFilters({
      category: 'all', privacyTechnology: 'all', accessType: 'all',
      priceRange: 'all', dataSize: 'all', dataAge: 'all', rating: 0
    });
    setSearchTerm('');
    setSortBy('relevance');
    setPage(1);
  };

  // === Helper Functions ===
  const formatDate = (date) => date ? new Date(date).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }) : 'N/A';
  const formatNumber = (num) => num?.toLocaleString() || 'N/A';
  const formatPrice = (price) => price === 0 ? 'Free' : `${price} PRIVA`;

  const getListingBadge = (listing) => {
    if (listing.isNew) return <span className="bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200 text-xs px-2.5 py-0.5 rounded">New</span>;
    if (listing.isTrending) return <span className="bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200 text-xs px-2.5 py-0.5 rounded">Trending</span>;
    if (listing.isFeatured) return <span className="bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200 text-xs px-2.5 py-0.5 rounded">Featured</span>;
    return null;
  };

  const getRatingStars = (rating) => {
    const stars = [];
    const fullStars = Math.floor(rating);
    const hasHalfStar = rating % 1 >= 0.5;
    for (let i = 0; i < fullStars; i++) stars.push(<Star key={`full-${i}`} className="w-4 h-4 text-yellow-500" />);
    if (hasHalfStar) stars.push(<StarHalf key="half" className="w-4 h-4 text-yellow-500" />);
    for (let i = 0; i < 5 - fullStars - (hasHalfStar ? 1 : 0); i++) stars.push(<Star key={`empty-${i}`} className="w-4 h-4 text-gray-300 dark:text-gray-600" />);
    return <div className="flex items-center">{stars} <span className="ml-1 text-sm text-gray-600 dark:text-gray-400">{rating.toFixed(1)}</span></div>;
  };

  const getPrivacyTechnologyIcon = (tech) => {
    const icons = {
      'differential-privacy': <Shield className="w-4 h-4" title="Differential Privacy" />,
      'federated-learning': <Shuffle className="w-4 h-4" title="Federated Learning" />,
      'secure-mpc': <Users className="w-4 h-4" title="Secure Multi-Party Computation" />,
      'zkp': <ZeroKnowledge className="w-4 h-4" title="Zero-Knowledge Proofs" />
    };
    return icons[tech] || <Lock className="w-4 h-4" title="Privacy Protection" />;
  };

  const getAccessTypeIcon = (type) => {
    const icons = {
      'open': <Eye className="w-4 h-4" title="Open Access" />,
      'restricted': <EyeOff className="w-4 h-4" title="Restricted Access" />,
      'purchase': <DollarSign className="w-4 h-4" title="Purchase Required" />
    };
    return icons[type] || <Lock className="w-4 h-4" title="Access Control" />;
  };

  // === Render Functions ===
  const renderFilters = () => (
    <div className="bg-white dark:bg-gray-800 p-4 rounded-lg shadow mb-6">
      <div className="flex flex-col md:flex-row gap-4 items-center">
        <div className="relative flex-1 w-full md:w-auto">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
          <input
            type="text"
            value={searchTerm}
            onChange={handleSearch}
            placeholder="Search datasets..."
            className="w-full pl-10 pr-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white"
            aria-label="Search datasets"
          />
        </div>
        <select
          value={filters.category}
          onChange={(e) => handleFilterChange('category', e.target.value)}
          className="w-full md:w-auto px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md dark:bg-gray-700 dark:text-white"
          aria-label="Filter by category"
        >
          <option value="all">All Categories</option>
          {categories.map(cat => <option key={cat} value={cat}>{cat}</option>)}
        </select>
        <select
          value={sortBy}
          onChange={(e) => handleSortChange(e.target.value)}
          className="w-full md:w-auto px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md dark:bg-gray-700 dark:text-white"
          aria-label="Sort by"
        >
          <option value="relevance">Relevance</option>
          <option value="price">Price</option>
          <option value="rating">Rating</option>
          <option value="date">Date</option>
        </select>
        <Button
          variant="outline"
          onClick={() => setShowAdvancedFilters(!showAdvancedFilters)}
          icon={<Sliders className="w-4 h-4" />}
        >
          Filters
        </Button>
        <Button variant="outline" onClick={handleClearFilters}>Clear</Button>
      </div>
      {showAdvancedFilters && (
        <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
          <select
            value={filters.privacyTechnology}
            onChange={(e) => handleFilterChange('privacyTechnology', e.target.value)}
            className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md dark:bg-gray-700 dark:text-white"
            aria-label="Filter by privacy technology"
          >
            <option value="all">All Privacy Tech</option>
            <option value="differential-privacy">Differential Privacy</option>
            <option value="federated-learning">Federated Learning</option>
            <option value="secure-mpc">Secure MPC</option>
            <option value="zkp">Zero-Knowledge Proofs</option>
          </select>
          <select
            value={filters.accessType}
            onChange={(e) => handleFilterChange('accessType', e.target.value)}
            className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md dark:bg-gray-700 dark:text-white"
            aria-label="Filter by access type"
          >
            <option value="all">All Access Types</option>
            <option value="open">Open</option>
            <option value="restricted">Restricted</option>
            <option value="purchase">Purchase</option>
          </select>
          <select
            value={filters.priceRange}
            onChange={(e) => handleFilterChange('priceRange', e.target.value)}
            className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md dark:bg-gray-700 dark:text-white"
            aria-label="Filter by price range"
          >
            <option value="all">All Prices</option>
            <option value="free">Free</option>
            <option value="low">1-50 PRIVA</option>
            <option value="medium">51-200 PRIVA</option>
            <option value="high">201+ PRIVA</option>
          </select>
          <select
            value={filters.dataSize}
            onChange={(e) => handleFilterChange('dataSize', e.target.value)}
            className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md dark:bg-gray-700 dark:text-white"
            aria-label="Filter by data size"
          >
            <option value="all">All Sizes</option>
            <option value="small">&lt;10K records</option>
            <option value="medium">10K-100K records</option>
            <option value="large">100K-1M records</option>
            <option value="very-large">&gt;1M records</option>
          </select>
        </div>
      )}
    </div>
  );

  const renderGridView = () => (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
      {currentListings.map(listing => (
        <Card key={listing.id} className="hover:shadow-lg transition-shadow" onClick={() => handleListingClick(listing)}>
          <div className="relative h-48 bg-gray-100 dark:bg-gray-800 rounded-t-lg overflow-hidden">
            {listing.thumbnailUrl ? (
              <img src={listing.thumbnailUrl} alt={listing.name} className="w-full h-full object-cover" />
            ) : (
              <Database className="w-16 h-16 text-blue-500 absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2" />
            )}
            <IconButton
              className="absolute top-2 right-2"
              onClick={(e) => { e.stopPropagation(); handleToggleFavorite(listing.id); }}
              aria-label={favoriteListings.includes(listing.id) ? "Remove from favorites" : "Add to favorites"}
            >
              <Heart
                className={`w-5 h-5 ${favoriteListings.includes(listing.id) ? 'text-red-500' : 'text-gray-400'}`}
                fill={favoriteListings.includes(listing.id) ? 'currentColor' : 'none'}
              />
            </IconButton>
            {getListingBadge(listing) && <div className="absolute top-2 left-2">{getListingBadge(listing)}</div>}
          </div>
          <div className="p-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white truncate">{listing.name}</h3>
            <p className="text-sm text-gray-600 dark:text-gray-400 line-clamp-2">{listing.description}</p>
            <div className="mt-2 text-sm text-gray-500 dark:text-gray-400 flex items-center">
              <Database className="w-4 h-4 mr-1" /> {formatNumber(listing.recordCount)} records
            </div>
            <div className="mt-1 text-sm text-gray-500 dark:text-gray-400 flex items-center">
              <Clock className="w-4 h-4 mr-1" /> Updated {formatDate(listing.updatedAt)}
            </div>
            <div className="mt-3 flex justify-between items-center">
              <div className="flex space-x-2">
                {listing.privacyTechnologies?.map(tech => (
                  <span key={tech}>{getPrivacyTechnologyIcon(tech)}</span>
                ))}
              </div>
              <span className="text-sm font-medium text-gray-900 dark:text-white">{formatPrice(listing.price)}</span>
            </div>
            <div className="mt-2 flex justify-between items-center">
              {getRatingStars(listing.rating)}
              {getAccessTypeIcon(listing.accessType)}
            </div>
          </div>
        </Card>
      ))}
    </div>
  );

  const renderListView = () => (
    <div className="overflow-x-auto rounded-lg border border-gray-200 dark:border-gray-700">
      <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
        <thead className="bg-gray-50 dark:bg-gray-800">
          <tr>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Dataset</th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Records</th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Updated</th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Privacy</th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Price</th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Actions</th>
          </tr>
        </thead>
        <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-700">
          {currentListings.map(listing => (
            <tr key={listing.id} className="hover:bg-gray-50 dark:hover:bg-gray-800 cursor-pointer" onClick={() => handleListingClick(listing)}>
              <td className="px-6 py-4 whitespace-nowrap">
                <div className="flex items-center">
                  <div className="h-10 w-10 rounded-full bg-blue-100 dark:bg-blue-900 flex items-center justify-center">
                    <Database className="h-5 w-5 text-blue-600 dark:text-blue-400" />
                  </div>
                  <div className="ml-4">
                    <div className="text-sm font-medium text-gray-900 dark:text-white">{listing.name}</div>
                    <div className="text-sm text-gray-500 dark:text-gray-400 truncate max-w-xs">{listing.description}</div>
                  </div>
                </div>
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">{formatNumber(listing.recordCount)}</td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">{formatDate(listing.updatedAt)}</td>
              <td className="px-6 py-4 whitespace-nowrap">
                <div className="flex space-x-2">
                  {listing.privacyTechnologies?.map(tech => (
                    <span key={tech}>{getPrivacyTechnologyIcon(tech)}</span>
                  ))}
                </div>
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">{formatPrice(listing.price)}</td>
              <td className="px-6 py-4 whitespace-nowrap">
                <IconButton
                  onClick={(e) => { e.stopPropagation(); handleToggleFavorite(listing.id); }}
                  aria-label={favoriteListings.includes(listing.id) ? "Remove from favorites" : "Add to favorites"}
                >
                  <Heart
                    className={`w-5 h-5 ${favoriteListings.includes(listing.id) ? 'text-red-500' : 'text-gray-400'}`}
                    fill={favoriteListings.includes(listing.id) ? 'currentColor' : 'none'}
                  />
                </IconButton>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );

  const renderPagination = () => (
    <div className="mt-6 flex justify-between items-center">
      <div className="text-sm text-gray-500 dark:text-gray-400">
        Showing {(page - 1) * pageSize + 1} to {Math.min(page * pageSize, listings.length)} of {listings.length} listings
      </div>
      <div className="flex space-x-2">
        <Button
          variant="outline"
          onClick={() => setPage(p => Math.max(p - 1, 1))}
          disabled={page === 1}
          aria-label="Previous page"
        >
          Previous
        </Button>
        <Button
          variant="outline"
          onClick={() => setPage(p => Math.min(p + 1, totalPages))}
          disabled={page === totalPages}
          aria-label="Next page"
        >
          Next
        </Button>
      </div>
    </div>
  );

  const renderDetailModal = () => (
    <Modal isOpen={showDetailModal} onClose={() => setShowDetailModal(false)} title={selectedListing?.name}>
      {selectedListing && (
        <div className="space-y-4">
          <p className="text-gray-600 dark:text-gray-400">{selectedListing.description}</p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <p><strong>Records:</strong> {formatNumber(selectedListing.recordCount)}</p>
              <p><strong>Updated:</strong> {formatDate(selectedListing.updatedAt)}</p>
              <p><strong>Price:</strong> {formatPrice(selectedListing.price)}</p>
              <p><strong>Category:</strong> {selectedListing.category}</p>
            </div>
            <div>
              <p><strong>Privacy Tech:</strong></p>
              <ul className="list-disc list-inside">
                {selectedListing.privacyTechnologies?.map(tech => (
                  <li key={tech} className="flex items-center">
                    {getPrivacyTechnologyIcon(tech)} <span className="ml-2">{tech}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
          <div className="flex space-x-2">
            <Button onClick={() => handleShowSampleData(selectedListing.id)} icon={<Eye className="w-4 h-4" />}>
              View Sample
            </Button>
            {selectedListing.accessType === 'restricted' && !selectedListing.hasAccess && (
              <Button onClick={() => setShowAccessRequestModal(true)} icon={<Lock className="w-4 h-4" />}>
                Request Access
              </Button>
            )}
            {selectedListing.accessType === 'purchase' && !selectedListing.hasAccess && (
              <Button onClick={() => handlePurchaseDataset(selectedListing.id)} icon={<DollarSign className="w-4 h-4" />}>
                Purchase
              </Button>
            )}
          </div>
        </div>
      )}
    </Modal>
  );

  const renderSampleDataModal = () => (
    <Modal isOpen={showSampleDataModal} onClose={() => setShowSampleDataModal(false)} title="Sample Data">
      {selectedListing?.sampleData ? (
        <pre className="bg-gray-100 dark:bg-gray-800 p-4 rounded overflow-auto max-h-96">
          {JSON.stringify(selectedListing.sampleData, null, 2)}
        </pre>
      ) : (
        <p>No sample data available.</p>
      )}
    </Modal>
  );

  const renderAccessRequestModal = () => (
    <Modal isOpen={showAccessRequestModal} onClose={() => setShowAccessRequestModal(false)} title="Request Access">
      <form onSubmit={(e) => {
        e.preventDefault();
        const accessDetails = { reason: e.target.reason.value };
        handleRequestAccess(selectedListing.id, accessDetails);
      }}>
        <div className="mb-4">
          <label htmlFor="reason" className="block text-sm font-medium text-gray-700 dark:text-gray-300">Reason for Access</label>
          <textarea
            id="reason"
            name="reason"
            rows="4"
            className="mt-1 block w-full border border-gray-300 dark:border-gray-600 rounded-md shadow-sm dark:bg-gray-700 dark:text-white"
            required
          />
        </div>
        <Button type="submit" disabled={isLoading}>Submit Request</Button>
      </form>
    </Modal>
  );

  // === Main Render ===
  return (
    <div className={`container mx-auto px-4 py-8 ${className}`} {...props}>
      {error && (
        <div className="mb-4 p-4 bg-red-100 dark:bg-red-900 text-red-700 dark:text-red-200 rounded flex items-center">
          <AlertTriangle className="w-5 h-5 mr-2" /> {error}
        </div>
      )}

      {renderFilters()}

      <div className="flex justify-between items-center mb-6">
        <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Marketplace Listings</h2>
        <div className="flex space-x-2">
          <IconButton
            onClick={() => setViewMode('grid')}
            className={viewMode === 'grid' ? 'text-blue-500' : 'text-gray-500'}
            aria-label="Grid view"
          >
            <Grid className="w-5 h-5" />
          </IconButton>
          <IconButton
            onClick={() => setViewMode('list')}
            className={viewMode === 'list' ? 'text-blue-500' : 'text-gray-500'}
            aria-label="List view"
          >
            <List className="w-5 h-5" />
          </IconButton>
        </div>
      </div>

      {isLoading ? (
        <div className="text-center py-16">
          <Zap className="animate-spin mx-auto h-12 w-12 text-blue-500" />
          <p className="mt-2 text-gray-600 dark:text-gray-400">Loading listings...</p>
        </div>
      ) : listings.length === 0 ? (
        <div className="text-center py-16">
          <Database className="mx-auto h-12 w-12 text-gray-400" />
          <h3 className="mt-2 text-lg font-medium text-gray-900 dark:text-white">No listings found</h3>
          <p className="mt-1 text-gray-500 dark:text-gray-400">Try adjusting your search or filters.</p>
          <Button variant="outline" onClick={handleClearFilters} className="mt-4">Clear Filters</Button>
        </div>
      ) : (
        <>
          {viewMode === 'grid' ? renderGridView() : renderListView()}
          {renderPagination()}
        </>
      )}

      {renderDetailModal()}
      {renderSampleDataModal()}
      {renderAccessRequestModal()}
    </div>
  );
};

// === PropTypes ===
Listings.propTypes = {
  userAddress: PropTypes.string,
  className: PropTypes.string
};

export default Listings;
