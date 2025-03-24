/**
 * DataDiscovery Component
 * 
 * A comprehensive interface for discovering, exploring, and requesting
 * access to privacy-preserving datasets on the PrivaSight platform.
 */

import React, { useState, useEffect, useMemo } from 'react';
import PropTypes from 'prop-types';
import { useDataVault } from '../../hooks/useDataVault';
import { usePrivacyLayer } from '../../hooks/usePrivacyLayer';

// Icons
import {
  Search,
  Filter,
  ChevronDown,
  Grid,
  List,
  Database,
  Eye,
  EyeOff,
  Shield,
  Users,
  Clock,
  Calendar,
  BarChart2,
  Lock,
  Bookmark,
  BookmarkCheck,
  Download,
  AlertTriangle,
  CheckCircle,
  X,
  UserPlus,
  Tag,
  Shuffle,
  ZeroKnowledge
} from '../icons';

// Components
import Button from '../common/Button';
import Card from '../common/Card';
import Modal from '../common/Modal';

// Placeholder for analytics visualization component
const DataPreview = ({ data, isLoading }) => (
  <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 h-64 flex items-center justify-center">
    {isLoading ? (
      <div className="animate-spin rounded-full h-10 w-10 border-4 border-blue-500 border-t-transparent"></div>
    ) : data ? (
      <div className="text-center">
        <BarChart2 className="h-16 w-16 mx-auto text-blue-500 mb-2" />
        <p className="text-sm text-gray-700 dark:text-gray-300">
          Preview generated with differential privacy (ε = 2.0)
        </p>
      </div>
    ) : (
      <div className="text-center">
        <Database className="h-16 w-16 mx-auto text-gray-400 mb-2" />
        <p className="text-sm text-gray-500 dark:text-gray-400">
          Select a dataset to preview
        </p>
      </div>
    )}
  </div>
);

DataPreview.propTypes = {
  data: PropTypes.object,
  isLoading: PropTypes.bool
};

const DataDiscovery = ({
  userAddress,
  className = '',
  ...props
}) => {
  // **State Management**
  const [datasets, setDatasets] = useState([]);
  const [selectedDataset, setSelectedDataset] = useState(null);
  const [previewData, setPreviewData] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [bookmarkedDatasets, setBookmarkedDatasets] = useState([]);
  const [searchParams, setSearchParams] = useState({
    query: '',
    category: 'all',
    privacyTechnology: 'all',
    sortBy: 'relevance',
    accessType: 'all'
  });
  const [viewMode, setViewMode] = useState('grid');
  const [page, setPage] = useState(1);
  const [pageSize] = useState(12);

  // Modal states
  const [showDatasetDetailModal, setShowDatasetDetailModal] = useState(false);
  const [showAccessRequestModal, setShowAccessRequestModal] = useState(false);
  const [accessRequestData, setAccessRequestData] = useState({
    accessLevel: 'read',
    purpose: '',
    additionalDetails: '',
    requestedDuration: 30,
    privacySettings: {
      differentialPrivacy: true,
      secureMpc: false,
      zkp: true,
      federatedLearning: false,
      privacyBudget: 1.0
    }
  });

  // **Custom Hooks**
  const {
    discoverDatasets,
    getDatasetDetails,
    getDatasetPreview,
    requestDatasetAccess,
    bookmarkDataset,
    removeBookmark,
    getBookmarkedDatasets
  } = useDataVault();

  const {
    generatePrivacyProof
  } = usePrivacyLayer();

  // **Effects**
  // Load datasets based on search parameters
  useEffect(() => {
    const loadDatasets = async () => {
      try {
        setIsLoading(true);
        const result = await discoverDatasets(searchParams);
        setDatasets(result.datasets);
        setError(null);
      } catch (err) {
        console.error('Failed to load datasets:', err);
        setError('Failed to load datasets. Please try again later.');
      } finally {
        setIsLoading(false);
      }
    };
    loadDatasets();
  }, [discoverDatasets, searchParams]);

  // Load bookmarked datasets
  useEffect(() => {
    const loadBookmarks = async () => {
      if (!userAddress) return;
      try {
        const bookmarked = await getBookmarkedDatasets(userAddress);
        setBookmarkedDatasets(bookmarked);
      } catch (err) {
        console.error('Failed to load bookmarks:', err);
      }
    };
    loadBookmarks();
  }, [userAddress, getBookmarkedDatasets]);

  // Load dataset details and preview
  useEffect(() => {
    const loadDatasetDetails = async () => {
      if (!selectedDataset) return;
      try {
        setIsLoading(true);
        const details = await getDatasetDetails(selectedDataset.id);
        setSelectedDataset({ ...selectedDataset, ...details });
        const preview = await getDatasetPreview(selectedDataset.id, {
          privacySettings: { differentialPrivacy: true, privacyBudget: 2.0 }
        });
        setPreviewData(preview);
        setError(null);
      } catch (err) {
        console.error('Failed to load dataset details:', err);
        setError('Failed to load dataset details.');
      } finally {
        setIsLoading(false);
      }
    };
    if (selectedDataset && showDatasetDetailModal) loadDatasetDetails();
  }, [selectedDataset?.id, showDatasetDetailModal, getDatasetDetails, getDatasetPreview]);

  // **Derived State**
  const paginatedDatasets = useMemo(() => {
    const startIndex = (page - 1) * pageSize;
    return datasets.slice(startIndex, startIndex + pageSize);
  }, [datasets, page, pageSize]);

  const totalPages = useMemo(() => Math.ceil(datasets.length / pageSize), [datasets, pageSize]);

  const isBookmarked = (datasetId) => bookmarkedDatasets.some(d => d.id === datasetId);

  // **Event Handlers**
  const handleSearch = () => setPage(1);

  const handleCategoryChange = (category) => {
    setSearchParams({ ...searchParams, category });
    setPage(1);
  };

  const handlePrivacyTechnologyChange = (technology) => {
    setSearchParams({ ...searchParams, privacyTechnology: technology });
    setPage(1);
  };

  const handleSortChange = (sortBy) => {
    setSearchParams({ ...searchParams, sortBy });
    setPage(1);
  };

  const handleAccessTypeChange = (accessType) => {
    setSearchParams({ ...searchParams, accessType });
    setPage(1);
  };

  const handleDatasetClick = (dataset) => {
    setSelectedDataset(dataset);
    setShowDatasetDetailModal(true);
  };

  const handleToggleBookmark = async (datasetId, isCurrentlyBookmarked) => {
    if (!userAddress) return;
    try {
      if (isCurrentlyBookmarked) {
        await removeBookmark(userAddress, datasetId);
        setBookmarkedDatasets(prev => prev.filter(d => d.id !== datasetId));
      } else {
        await bookmarkDataset(userAddress, datasetId);
        const dataset = datasets.find(d => d.id === datasetId);
        setBookmarkedDatasets(prev => [...prev, dataset]);
      }
    } catch (err) {
      console.error('Failed to update bookmark:', err);
      setError('Failed to update bookmarks.');
    }
  };

  const handleRequestAccess = async () => {
    if (!selectedDataset || !userAddress) return;
    try {
      setIsLoading(true);
      let privacyProof = null;
      if (accessRequestData.privacySettings.zkp) {
        privacyProof = await generatePrivacyProof(userAddress, selectedDataset.id);
      }
      await requestDatasetAccess(
        userAddress,
        selectedDataset.id,
        accessRequestData.accessLevel,
        accessRequestData.purpose,
        {
          additionalDetails: accessRequestData.additionalDetails,
          requestedDuration: accessRequestData.requestedDuration,
          privacySettings: accessRequestData.privacySettings,
          privacyProof
        }
      );
      setShowAccessRequestModal(false);
      setSelectedDataset({ ...selectedDataset, accessRequestStatus: 'pending' });
      setAccessRequestData({
        accessLevel: 'read',
        purpose: '',
        additionalDetails: '',
        requestedDuration: 30,
        privacySettings: { differentialPrivacy: true, secureMpc: false, zkp: true, federatedLearning: false, privacyBudget: 1.0 }
      });
      setError(null);
    } catch (err) {
      console.error('Failed to request access:', err);
      setError('Failed to request access.');
    } finally {
      setIsLoading(false);
    }
  };

  // **Helper Functions**
  const formatDate = (date) => date ? new Date(date).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }) : 'N/A';
  const formatNumber = (num) => num?.toLocaleString() || 'N/A';

  const getPrivacyTechnologyIcon = (technology) => {
    switch (technology) {
      case 'differential-privacy': return <Shield className="w-4 h-4" title="Differential Privacy" />;
      case 'federated-learning': return <Shuffle className="w-4 h-4" title="Federated Learning" />;
      case 'secure-mpc': return <Users className="w-4 h-4" title="Secure Multi-Party Computation" />;
      case 'zero-knowledge-proofs': return <ZeroKnowledge className="w-4 h-4" title="Zero-Knowledge Proofs" />;
      default: return <Lock className="w-4 h-4" title="Privacy Protection" />;
    }
  };

  const getAccessRequestStatusBadge = (status) => {
    const colors = {
      pending: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200",
      approved: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
      rejected: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200",
      expired: "bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200"
    };
    return (
      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${colors[status]}`}>
        {status.charAt(0).toUpperCase() + status.slice(1)}
      </span>
    );
  };

  // **Render Helpers**
  const renderEmptyState = () => (
    <div className="text-center py-16">
      <Database className="mx-auto h-12 w-12 text-gray-400" />
      <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No datasets found</h3>
      <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">Try changing your search criteria or check back later.</p>
    </div>
  );

  const renderGridView = () => (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
      {paginatedDatasets.map((dataset) => (
        <Card key={dataset.id} className="cursor-pointer hover:shadow-md transition-shadow" onClick={() => handleDatasetClick(dataset)}>
          <div className="relative">
            <div className="h-36 flex items-center justify-center bg-gray-100 dark:bg-gray-800 rounded-t-lg">
              <Database className="h-16 w-16 text-blue-500 dark:text-blue-400" />
            </div>
            <button
              className="absolute top-2 right-2 p-1 rounded-full bg-white dark:bg-gray-700 shadow hover:bg-gray-100 dark:hover:bg-gray-600"
              onClick={(e) => { e.stopPropagation(); handleToggleBookmark(dataset.id, isBookmarked(dataset.id)); }}
              aria-label={isBookmarked(dataset.id) ? "Remove bookmark" : "Add bookmark"}
            >
              {isBookmarked(dataset.id) ? <BookmarkCheck className="w-5 h-5 text-blue-500" /> : <Bookmark className="w-5 h-5 text-gray-400 hover:text-blue-500" />}
            </button>
          </div>
          <div className="p-4">
            <div className="flex items-start justify-between">
              <h3 className="text-base font-medium text-gray-900 dark:text-white truncate" title={dataset.name}>{dataset.name}</h3>
              {dataset.accessRequestStatus && getAccessRequestStatusBadge(dataset.accessRequestStatus)}
            </div>
            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400 line-clamp-2" title={dataset.description}>{dataset.description}</p>
            <div className="mt-3 flex items-center text-sm text-gray-500 dark:text-gray-400">
              <Database className="flex-shrink-0 mr-1.5 h-4 w-4" />
              <span>{formatNumber(dataset.recordCount)} records</span>
            </div>
            <div className="mt-2 flex items-center text-sm text-gray-500 dark:text-gray-400">
              <Calendar className="flex-shrink-0 mr-1.5 h-4 w-4" />
              <span>Updated {formatDate(dataset.updatedAt)}</span>
            </div>
            <div className="mt-4 flex items-center justify-between">
              <div className="flex space-x-2">
                {dataset.privacyTechnologies?.map((tech) => (
                  <span key={tech} className="text-gray-600 dark:text-gray-300">{getPrivacyTechnologyIcon(tech)}</span>
                ))}
              </div>
              <div>
                {dataset.isPublic ? (
                  <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
                    <Eye className="mr-1 h-3 w-3" /> Public
                  </span>
                ) : (
                  <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200">
                    <EyeOff className="mr-1 h-3 w-3" /> Private
                  </span>
                )}
              </div>
            </div>
          </div>
        </Card>
      ))}
    </div>
  );

  const renderListView = () => (
    <div className="overflow-hidden rounded-lg border border-gray-200 dark:border-gray-700">
      <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
        <thead className="bg-gray-50 dark:bg-gray-800">
          <tr>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Dataset</th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Records</th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Updated</th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Privacy</th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Status</th>
            <th className="relative px-6 py-3"><span className="sr-only">Actions</span></th>
          </tr>
        </thead>
        <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-700">
          {paginatedDatasets.map((dataset) => (
            <tr key={dataset.id} className="hover:bg-gray-50 dark:hover:bg-gray-800 cursor-pointer" onClick={() => handleDatasetClick(dataset)}>
              <td className="px-6 py-4 whitespace-nowrap">
                <div className="flex items-center">
                  <div className="flex-shrink-0 h-10 w-10 rounded-full bg-blue-100 dark:bg-blue-900 flex items-center justify-center">
                    <Database className="h-5 w-5 text-blue-600 dark:text-blue-400" />
                  </div>
                  <div className="ml-4">
                    <div className="text-sm font-medium text-gray-900 dark:text-white">{dataset.name}</div>
                    <div className="text-sm text-gray-500 dark:text-gray-400 max-w-xs truncate">{dataset.description}</div>
                  </div>
                </div>
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                <div className="text-sm text-gray-900 dark:text-white">{formatNumber(dataset.recordCount)}</div>
                <div className="text-sm text-gray-500 dark:text-gray-400">{dataset.category}</div>
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                <div className="text-sm text-gray-900 dark:text-white">{formatDate(dataset.updatedAt)}</div>
                <div className="text-sm text-gray-500 dark:text-gray-400">Created: {formatDate(dataset.createdAt)}</div>
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                <div className="flex items-center space-x-1">
                  {dataset.privacyTechnologies?.map((tech) => (
                    <span key={tech} className="text-gray-500" title={tech}>{getPrivacyTechnologyIcon(tech)}</span>
                  ))}
                </div>
                <div className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                  {dataset.isPublic ? (
                    <span className="inline-flex items-center text-xs"><Eye className="mr-1 h-3 w-3" /> Public</span>
                  ) : (
                    <span className="inline-flex items-center text-xs"><EyeOff className="mr-1 h-3 w-3" /> Private</span>
                  )}
                </div>
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                {dataset.accessRequestStatus ? (
                  getAccessRequestStatusBadge(dataset.accessRequestStatus)
                ) : (
                  <Button
                    variant="primary"
                    size="small"
                    onClick={(e) => { e.stopPropagation(); setSelectedDataset(dataset); setShowAccessRequestModal(true); }}
                  >
                    Request Access
                  </Button>
                )}
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                <button
                  onClick={(e) => { e.stopPropagation(); handleToggleBookmark(dataset.id, isBookmarked(dataset.id)); }}
                  className={`text-gray-400 hover:text-blue-500 ${isBookmarked(dataset.id) ? 'text-blue-500' : ''}`}
                >
                  {isBookmarked(dataset.id) ? <BookmarkCheck className="w-5 h-5" /> : <Bookmark className="w-5 h-5" />}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );

  const renderPagination = () => (
    <div className="mt-4 flex items-center justify-between">
      <div className="flex items-center text-gray-500 dark:text-gray-400 text-sm">
        Showing <span className="font-medium mx-1">{(page - 1) * pageSize + 1}</span> to <span className="font-medium mx-1">{Math.min(page * pageSize, datasets.length)}</span> of <span className="font-medium mx-1">{datasets.length}</span> datasets
      </div>
      <div className="flex justify-end">
        <button
          className="inline-flex items-center px-3 py-1.5 border border-gray-300 dark:border-gray-600 rounded-l-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed"
          onClick={() => setPage(page => Math.max(page - 1, 1))}
          disabled={page <= 1}
        >
          Previous
        </button>
        <button
          className="inline-flex items-center px-3 py-1.5 border border-gray-300 dark:border-gray-600 border-l-0 rounded-r-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed"
          onClick={() => setPage(page => Math.min(page + 1, totalPages))}
          disabled={page >= totalPages}
        >
          Next
        </button>
      </div>
    </div>
  );

  // **Main Render**
  return (
    <div className={`data-discovery-container ${className}`} {...props}>
      {/* Header */}
      <div className="mb-6 flex flex-col sm:flex-row sm:justify-between sm:items-center space-y-4 sm:space-y-0">
        <div>
          <h2 className="text-xl font-bold text-gray-900 dark:text-white">Discover Datasets</h2>
          <p className="text-sm text-gray-500 dark:text-gray-400">Find privacy-preserving datasets and request access</p>
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="mb-6 bg-red-50 dark:bg-red-900/20 p-4 rounded-lg">
          <div className="flex">
            <AlertTriangle className="h-5 w-5 text-red-500" />
            <div className="ml-3">
              <p className="text-sm text-red-700 dark:text-red-300">{error}</p>
            </div>
          </div>
        </div>
      )}

      {/* Search and Filters */}
      <div className="mb-6 bg-white dark:bg-gray-800 rounded-lg shadow p-4">
        <div className="flex flex-col space-y-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
            <input
              type="text"
              placeholder="Search datasets..."
              value={searchParams.query}
              onChange={(e) => setSearchParams({ ...searchParams, query: e.target.value })}
              onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
              className="pl-10 pr-3 py-2 w-full border border-gray-300 dark:border-gray-700 rounded-md text-gray-900 dark:text-white bg-white dark:bg-gray-800 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
            <div className="relative">
              <label htmlFor="category" className="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">Category</label>
              <select
                id="category"
                value={searchParams.category}
                onChange={(e) => handleCategoryChange(e.target.value)}
                className="appearance-none block w-full bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-md py-2 pl-3 pr-8 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="all">All Categories</option>
                <option value="healthcare">Healthcare</option>
                <option value="finance">Finance</option>
                <option value="marketing">Marketing</option>
                <option value="sales">Sales</option>
                <option value="hr">Human Resources</option>
                <option value="research">Research</option>
                <option value="other">Other</option>
              </select>
              <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2 text-gray-700 dark:text-gray-300 top-6">
                <ChevronDown className="h-4 w-4" />
              </div>
            </div>
            <div className="relative">
              <label htmlFor="privacyTechnology" className="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">Privacy Technology</label>
              <select
                id="privacyTechnology"
                value={searchParams.privacyTechnology}
                onChange={(e) => handlePrivacyTechnologyChange(e.target.value)}
                className="appearance-none block w-full bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-md py-2 pl-3 pr-8 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="all">All Technologies</option>
                <option value="differential-privacy">Differential Privacy</option>
                <option value="federated-learning">Federated Learning</option>
                <option value="secure-mpc">Secure MPC</option>
                <option value="zero-knowledge-proofs">Zero-Knowledge Proofs</option>
              </select>
              <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2 text-gray-700 dark:text-gray-300 top-6">
                <ChevronDown className="h-4 w-4" />
              </div>
            </div>
            <div className="relative">
              <label htmlFor="sortBy" className="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">Sort By</label>
              <select
                id="sortBy"
                value={searchParams.sortBy}
                onChange={(e) => handleSortChange(e.target.value)}
                className="appearance-none block w-full bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-md py-2 pl-3 pr-8 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="relevance">Relevance</option>
                <option value="newest">Newest First</option>
                <option value="oldest">Oldest First</option>
                <option value="largest">Largest First</option>
                <option value="name">Name (A-Z)</option>
              </select>
              <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2 text-gray-700 dark:text-gray-300 top-6">
                <ChevronDown className="h-4 w-4" />
              </div>
            </div>
            <div className="relative">
              <label htmlFor="accessType" className="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">Access Type</label>
              <select
                id="accessType"
                value={searchParams.accessType}
                onChange={(e) => handleAccessTypeChange(e.target.value)}
                className="appearance-none block w-full bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-md py-2 pl-3 pr-8 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="all">All Datasets</option>
                <option value="public">Public Only</option>
                <option value="bookmarked">Bookmarked</option>
                <option value="requested">Requested Access</option>
                <option value="granted">Access Granted</option>
              </select>
              <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2 text-gray-700 dark:text-gray-300 top-6">
                <ChevronDown className="h-4 w-4" />
              </div>
            </div>
          </div>
          <div className="flex justify-between">
            <div className="flex space-x-2">
              <button
                className={`px-2 py-1 rounded ${viewMode === 'grid' ? 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200' : 'bg-white dark:bg-gray-800 text-gray-600 dark:text-gray-300'}`}
                onClick={() => setViewMode('grid')}
                aria-label="Grid view"
              >
                <Grid className="h-5 w-5" />
              </button>
              <button
                className={`px-2 py-1 rounded ${viewMode === 'list' ? 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200' : 'bg-white dark:bg-gray-800 text-gray-600 dark:text-gray-300'}`}
                onClick={() => setViewMode('list')}
                aria-label="List view"
              >
                <List className="h-5 w-5" />
              </button>
            </div>
            <Button variant="primary" icon={<Search className="w-4 h-4" />} onClick={handleSearch}>
              Search
            </Button>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="mb-6">
        {isLoading && !datasets.length ? (
          <div className="py-16 flex justify-center">
            <div className="animate-spin rounded-full h-10 w-10 border-4 border-blue-500 border-t-transparent"></div>
          </div>
        ) : !datasets.length ? (
          renderEmptyState()
        ) : (
          <>
            {viewMode === 'grid' ? renderGridView() : renderListView()}
            {totalPages > 1 && renderPagination()}
          </>
        )}
      </div>

      {/* Modals */}
      <Modal
        isOpen={showDatasetDetailModal}
        onClose={() => { setShowDatasetDetailModal(false); setSelectedDataset(null); }}
        title={selectedDataset?.name}
        size="large"
        footer={
          <div className="flex justify-end space-x-3">
            <Button variant="secondary" onClick={() => setShowDatasetDetailModal(false)}>Close</Button>
            {selectedDataset && !selectedDataset.accessRequestStatus && (
              <Button
                variant="primary"
                onClick={() => { setShowDatasetDetailModal(false); setShowAccessRequestModal(true); }}
                icon={<UserPlus className="w-4 h-4" />}
              >
                Request Access
              </Button>
            )}
            {selectedDataset && selectedDataset.accessRequestStatus === 'approved' && (
              <Button variant="primary" icon={<Download className="w-4 h-4" />}>Access Data</Button>
            )}
          </div>
        }
      >
        {selectedDataset && (
          <div className="space-y-6">
            <div className="bg-gray-50 dark:bg-gray-800 p-4 rounded-lg">
              <div className="flex items-start">
                <div className="flex items-center space-x-2">
                  {selectedDataset.isPublic ? (
                    <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
                      <Eye className="mr-1 h-3 w-3" /> Public
                    </span>
                  ) : (
                    <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200">
                      <EyeOff className="mr-1 h-3 w-3" /> Private
                    </span>
                  )}
                  {selectedDataset.category && (
                    <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200">
                      {selectedDataset.category}
                    </span>
                  )}
                  {selectedDataset.accessRequestStatus && getAccessRequestStatusBadge(selectedDataset.accessRequestStatus)}
                </div>
              </div>
              <p className="mt-3 text-gray-700 dark:text-gray-300">{selectedDataset.description}</p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Dataset Details</h3>
                <div className="space-y-4">
                  <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
                    <dl className="divide-y divide-gray-200 dark:divide-gray-700">
                      <div className="px-4 py-3 grid grid-cols-2 gap-4">
                        <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Owner</dt>
                        <dd className="text-sm text-gray-900 dark:text-white">{selectedDataset.ownerName || 'Anonymous'}</dd>
                      </div>
                      <div className="px-4 py-3 grid grid-cols-2 gap-4">
                        <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Records</dt>
                        <dd className="text-sm text-gray-900 dark:text-white">{formatNumber(selectedDataset.recordCount)}</dd>
                      </div>
                      <div className="px-4 py-3 grid grid-cols-2 gap-4">
                        <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Fields</dt>
                        <dd className="text-sm text-gray-900 dark:text-white">{formatNumber(selectedDataset.fieldCount)}</dd>
                      </div>
                      <div className="px-4 py-3 grid grid-cols-2 gap-4">
                        <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Created</dt>
                        <dd className="text-sm text-gray-900 dark:text-white">{formatDate(selectedDataset.createdAt)}</dd>
                      </div>
                      <div className="px-4 py-3 grid grid-cols-2 gap-4">
                        <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Updated</dt>
                        <dd className="text-sm text-gray-900 dark:text-white">{formatDate(selectedDataset.updatedAt)}</dd>
                      </div>
                      <div className="px-4 py-3 grid grid-cols-2 gap-4">
                        <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">License</dt>
                        <dd className="text-sm text-gray-900 dark:text-white">{selectedDataset.license || 'Private'}</dd>
                      </div>
                    </dl>
                  </div>
                  <div>
                    <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-2">Privacy Technologies</h4>
                    <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
                      {selectedDataset.privacyTechnologies?.length > 0 ? (
                        <div className="space-y-3">
                          {selectedDataset.privacyTechnologies.includes('differential-privacy') && (
                            <div className="flex items-start">
                              <Shield className="h-5 w-5 text-blue-500 mt-0.5" />
                              <div className="ml-3">
                                <h5 className="text-sm font-medium text-gray-900 dark:text-white">Differential Privacy</h5>
                                <p className="text-xs text-gray-500 dark:text-gray-400">Protects individual data points.</p>
                              </div>
                            </div>
                          )}
                          {selectedDataset.privacyTechnologies.includes('federated-learning') && (
                            <div className="flex items-start">
                              <Shuffle className="h-5 w-5 text-green-500 mt-0.5" />
                              <div className="ml-3">
                                <h5 className="text-sm font-medium text-gray-900 dark:text-white">Federated Learning</h5>
                                <p className="text-xs text-gray-500 dark:text-gray-400">Trains models decentrally.</p>
                              </div>
                            </div>
                          )}
                          {selectedDataset.privacyTechnologies.includes('secure-mpc') && (
                            <div className="flex items-start">
                              <Users className="h-5 w-5 text-purple-500 mt-0.5" />
                              <div className="ml-3">
                                <h5 className="text-sm font-medium text-gray-900 dark:text-white">Secure MPC</h5>
                                <p className="text-xs text-gray-500 dark:text-gray-400">Encrypts computations.</p>
                              </div>
                            </div>
                          )}
                          {selectedDataset.privacyTechnologies.includes('zero-knowledge-proofs') && (
                            <div className="flex items-start">
                              <ZeroKnowledge className="h-5 w-5 text-yellow-500 mt-0.5" />
                              <div className="ml-3">
                                <h5 className="text-sm font-medium text-gray-900 dark:text-white">Zero-Knowledge Proofs</h5>
                                <p className="text-xs text-gray-500 dark:text-gray-400">Verifies without revealing.</p>
                              </div>
                            </div>
                          )}
                        </div>
                      ) : (
                        <p className="text-sm text-gray-500 dark:text-gray-400">No privacy technologies listed.</p>
                      )}
                    </div>
                  </div>
                  {selectedDataset.tags?.length > 0 && (
                    <div>
                      <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-2">Tags</h4>
                      <div className="flex flex-wrap gap-2">
                        {selectedDataset.tags.map((tag) => (
                          <span key={tag} className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200">
                            <Tag className="mr-1 h-3 w-3" /> {tag}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
              <div>
                <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Privacy-Preserving Preview</h3>
                <div className="space-y-4">
                  <DataPreview data={previewData} isLoading={isLoading} />
                  <div className="bg-blue-50 dark:bg-blue-900/20 p-4 rounded-lg">
                    <div className="flex">
                      <Shield className="h-5 w-5 text-blue-500" />
                      <div className="ml-3">
                        <h4 className="text-sm font-medium text-blue-800 dark:text-blue-200">Privacy Notice</h4>
                        <p className="mt-1 text-xs text-blue-700 dark:text-blue-300">
                          This preview uses differential privacy to protect data.
                        </p>
                      </div>
                    </div>
                  </div>
                  {selectedDataset.schema && (
                    <div>
                      <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-2">Schema Preview</h4>
                      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
                        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                          <thead className="bg-gray-50 dark:bg-gray-700">
                            <tr>
                              <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Field</th>
                              <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Type</th>
                              <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Sensitivity</th>
                            </tr>
                          </thead>
                          <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                            {selectedDataset.schema.slice(0, 5).map((field, idx) => (
                              <tr key={idx}>
                                <td className="px-3 py-2 whitespace-nowrap text-sm text-gray-900 dark:text-white">{field.name}</td>
                                <td className="px-3 py-2 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">{field.type}</td>
                                <td className="px-3 py-2 whitespace-nowrap">
                                  {field.sensitivity === 'high' ? (
                                    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200">High</span>
                                  ) : field.sensitivity === 'medium' ? (
                                    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200">Medium</span>
                                  ) : (
                                    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">Low</span>
                                  )}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                          {selectedDataset.schema.length > 5 && (
                            <tfoot className="bg-gray-50 dark:bg-gray-700">
                              <tr>
                                <td colSpan="3" className="px-3 py-2 text-sm text-gray-500 dark:text-gray-400 text-center">
                                  + {selectedDataset.schema.length - 5} more fields
                                </td>
                              </tr>
                            </tfoot>
                          )}
                        </table>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
            {selectedDataset.accessRequestStatus && (
              <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">Access Request Status</h3>
                <div className="space-y-3">
                  <div className="flex justify-between items-center">
                    <div className="flex items-center">
                      <div className={`flex-shrink-0 h-9 w-9 rounded-full flex items-center justify-center ${selectedDataset.accessRequestStatus === 'approved' ? 'bg-green-100 dark:bg-green-900' : selectedDataset.accessRequestStatus === 'rejected' ? 'bg-red-100 dark:bg-red-900' : 'bg-yellow-100 dark:bg-yellow-900'}`}>
                        {selectedDataset.accessRequestStatus === 'approved' ? <CheckCircle className="h-5 w-5 text-green-600 dark:text-green-400" /> : selectedDataset.accessRequestStatus === 'rejected' ? <X className="h-5 w-5 text-red-600 dark:text-red-400" /> : <Clock className="h-5 w-5 text-yellow-600 dark:text-yellow-400" />}
                      </div>
                      <div className="ml-3">
                        <p className="text-sm font-medium text-gray-900 dark:text-white">
                          {selectedDataset.accessRequestStatus === 'approved' ? 'Access Approved' : selectedDataset.accessRequestStatus === 'rejected' ? 'Access Rejected' : 'Request Pending'}
                        </p>
                        <p className="text-xs text-gray-500 dark:text-gray-400">Requested on {formatDate(selectedDataset.accessRequestDate)}</p>
                      </div>
                    </div>
                    {selectedDataset.accessRequestStatus === 'approved' && (
                      <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
                        Expires: {formatDate(selectedDataset.accessExpiryDate || 'Never')}
                      </span>
                    )}
                  </div>
                  {selectedDataset.accessRequestStatus === 'rejected' && selectedDataset.rejectionReason && (
                    <div className="bg-red-50 dark:bg-red-900/20 p-3 rounded-md">
                      <p className="text-sm text-red-700 dark:text-red-300"><span className="font-medium">Reason: </span>{selectedDataset.rejectionReason}</p>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}
      </Modal>

      <Modal
        isOpen={showAccessRequestModal}
        onClose={() => setShowAccessRequestModal(false)}
        title="Request Dataset Access"
        size="large"
        variant="primary"
      >
        {selectedDataset && (
          <div className="space-y-6">
            <div className="bg-blue-50 dark:bg-blue-900/20 p-4 rounded-lg">
              <div className="flex">
                <Shield className="h-6 w-6 text-blue-500" />
                <div className="ml-3">
                  <h3 className="text-sm font-medium text-blue-800 dark:text-blue-200">Privacy-Preserving Access</h3>
                  <p className="mt-1 text-sm text-blue-700 dark:text-blue-300">
                    Requesting access to <span className="font-medium">{selectedDataset.name}</span>. Protected by privacy technologies.
                  </p>
                </div>
              </div>
            </div>
            <div className="space-y-4">
              <div>
                <label htmlFor="accessLevel" className="block text-sm font-medium text-gray-700 dark:text-gray-300">Access Level <span className="text-red-500">*</span></label>
                <select
                  id="accessLevel"
                  value={accessRequestData.accessLevel}
                  onChange={(e) => setAccessRequestData({ ...accessRequestData, accessLevel: e.target.value })}
                  className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-700 dark:bg-gray-800 dark:text-white shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                >
                  <option value="read">Read (View data only)</option>
                  <option value="compute">Compute (Run privacy-preserving computations)</option>
                  {selectedDataset.allowWriteAccess && <option value="write">Write (Modify data)</option>}
                </select>
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">Determines your permissions.</p>
              </div>
              <div>
                <label htmlFor="purpose" className="block text-sm font-medium text-gray-700 dark:text-gray-300">Access Purpose <span className="text-red-500">*</span></label>
                <textarea
                  id="purpose"
                  value={accessRequestData.purpose}
                  onChange={(e) => setAccessRequestData({ ...accessRequestData, purpose: e.target.value })}
                  rows={3}
                  className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-700 dark:bg-gray-800 dark:text-white shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                  placeholder="Explain why you need access and how you will use it."
                  required
                />
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">Describe your intended use.</p>
              </div>
              <div>
                <label htmlFor="additionalDetails" className="block text-sm font-medium text-gray-700 dark:text-gray-300">Additional Details</label>
                <textarea
                  id="additionalDetails"
                  value={accessRequestData.additionalDetails}
                  onChange={(e) => setAccessRequestData({ ...accessRequestData, additionalDetails: e.target.value })}
                  rows={2}
                  className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-700 dark:bg-gray-800 dark:text-white shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                  placeholder="Any additional information..."
                />
              </div>
              <div>
                <label htmlFor="requestedDuration" className="block text-sm font-medium text-gray-700 dark:text-gray-300">Requested Duration (Days)</label>
                <input
                  type="number"
                  id="requestedDuration"
                  value={accessRequestData.requestedDuration}
                  onChange={(e) => setAccessRequestData({ ...accessRequestData, requestedDuration: parseInt(e.target.value) })}
                  min="1"
                  max="365"
                  className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-700 dark:bg-gray-800 dark:text-white shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                />
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">Duration of access (1-365 days).</p>
              </div>
            </div>
            <div>
              <h3 className="text-sm font-medium text-gray-900 dark:text-white mb-2">Privacy Requirements</h3>
              <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                <div className="space-y-4">
                  <div className="flex items-start">
                    <input
                      id="differentialPrivacy"
                      type="checkbox"
                      checked={accessRequestData.privacySettings.differentialPrivacy}
                      onChange={(e) => setAccessRequestData({ ...accessRequestData, privacySettings: { ...accessRequestData.privacySettings, differentialPrivacy: e.target.checked } })}
                      className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded dark:border-gray-700 dark:bg-gray-800"
                    />
                    <label htmlFor="differentialPrivacy" className="ml-3 block text-sm font-medium text-gray-700 dark:text-gray-300">Differential Privacy</label>
                    <p className="ml-3 text-xs text-gray-500 dark:text-gray-400">Adds noise to protect data.</p>
                  </div>
                  <div className="flex items-start">
                    <input
                      id="secureMpc"
                      type="checkbox"
                      checked={accessRequestData.privacySettings.secureMpc}
                      onChange={(e) => setAccessRequestData({ ...accessRequestData, privacySettings: { ...accessRequestData.privacySettings, secureMpc: e.target.checked } })}
                      className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded dark:border-gray-700 dark:bg-gray-800"
                    />
                    <label htmlFor="secureMpc" className="ml-3 block text-sm font-medium text-gray-700 dark:text-gray-300">Secure Multi-Party Computation</label>
                    <p className="ml-3 text-xs text-gray-500 dark:text-gray-400">Encrypts computations.</p>
                  </div>
                  <div className="flex items-start">
                    <input
                      id="zkp"
                      type="checkbox"
                      checked={accessRequestData.privacySettings.zkp}
                      onChange={(e) => setAccessRequestData({ ...accessRequestData, privacySettings: { ...accessRequestData.privacySettings, zkp: e.target.checked } })}
                      className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded dark:border-gray-700 dark:bg-gray-800"
                    />
                    <label htmlFor="zkp" className="ml-3 block text-sm font-medium text-gray-700 dark:text-gray-300">Zero-Knowledge Proofs</label>
                    <p className="ml-3 text-xs text-gray-500 dark:text-gray-400">Verifies without revealing.</p>
                  </div>
                  <div className="flex items-start">
                    <input
                      id="federatedLearning"
                      type="checkbox"
                      checked={accessRequestData.privacySettings.federatedLearning}
                      onChange={(e) => setAccessRequestData({ ...accessRequestData, privacySettings: { ...accessRequestData.privacySettings, federatedLearning: e.target.checked } })}
                      className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded dark:border-gray-700 dark:bg-gray-800"
                    />
                    <label htmlFor="federatedLearning" className="ml-3 block text-sm font-medium text-gray-700 dark:text-gray-300">Federated Learning</label>
                    <p className="ml-3 text-xs text-gray-500 dark:text-gray-400">Trains models decentrally.</p>
                  </div>
                </div>
              </div>
            </div>
            <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
              <div className="flex items-start mb-4">
                <input id="termsAgreement" type="checkbox" required className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded dark:border-gray-700 dark:bg-gray-800" />
                <label htmlFor="termsAgreement" className="ml-3 block text-sm font-medium text-gray-700 dark:text-gray-300">Terms Agreement</label>
                <p className="ml-3 text-xs text-gray-500 dark:text-gray-400">I agree to the terms and privacy policy.</p>
              </div>
              <div className="flex items-start">
                <input id="privacyConsent" type="checkbox" required className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded dark:border-gray-700 dark:bg-gray-800" />
                <label htmlFor="privacyConsent" className="ml-3 block text-sm font-medium text-gray-700 dark:text-gray-300">Privacy Consent</label>
                <p className="ml-3 text-xs text-gray-500 dark:text-gray-400">I consent to zero-knowledge proofs for verification.</p>
              </div>
            </div>
            <div className="flex justify-end space-x-3 pt-4 border-t border-gray-200 dark:border-gray-700">
              <Button variant="secondary" onClick={() => setShowAccessRequestModal(false)}>Cancel</Button>
              <Button variant="primary" onClick={handleRequestAccess} isLoading={isLoading} isDisabled={!accessRequestData.purpose}>Submit Request</Button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
};

DataDiscovery.propTypes = {
  userAddress: PropTypes.string.isRequired,
  className: PropTypes.string,
};

export default DataDiscovery;
