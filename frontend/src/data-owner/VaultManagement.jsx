/**
 * VaultManagement Component
 * 
 * A comprehensive UI for managing data vaults in the PrivaSight platform.
 * Allows data owners to create, view, and manage access to their data vaults
 * with strong privacy controls.
 */

import React, { useState, useEffect, useMemo } from 'react';
import PropTypes from 'prop-types';
import { useDataVault } from '../../hooks/useDataVault';
import { usePrivacyLayer } from '../../hooks/usePrivacyLayer';
import { usePrivaToken } from '../../hooks/usePrivaToken';

// Icons
import {
  Shield,
  Eye,
  EyeOff,
  Lock,
  Unlock,
  Plus,
  Trash,
  Edit,
  Share,
  Users,
  Clock,
  Filter,
  ChevronDown,
  Database,
  Activity,
  Settings,
  AlertTriangle,
  CheckCircle,
  UserPlus,
  UserMinus,
  Search,
  MoreVertical,
  ExternalLink,
  Download,
  Upload,
  FileText,
  ZeroKnowledge
} from '../icons';

// Components
import Button, { ActionButton, IconButton } from '../common/Button';
import Card, { DataVaultCard } from '../common/Card';
import Modal, { PrivacySettingsModal, DataVaultAccessModal } from '../common/Modal';
import DataUpload from './DataUpload';

const VaultManagement = ({
  userAddress,
  className = '',
  ...props
}) => {
  // ==== State Management ====
  const [vaults, setVaults] = useState([]);
  const [selectedVault, setSelectedVault] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState('all');
  const [sortOrder, setSortOrder] = useState('newest');
  const [page, setPage] = useState(1);
  const [pageSize] = useState(10);

  // Modal states
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [showVaultDetailModal, setShowVaultDetailModal] = useState(false);
  const [showAccessControlModal, setShowAccessControlModal] = useState(false);
  const [showPrivacySettingsModal, setShowPrivacySettingsModal] = useState(false);
  const [showDeleteConfirmModal, setShowDeleteConfirmModal] = useState(false);
  const [showAccessRequestsModal, setShowAccessRequestsModal] = useState(false);

  // Detailed states
  const [accessRequests, setAccessRequests] = useState([]);
  const [vaultAccessLog, setVaultAccessLog] = useState([]);
  const [vaultMetrics, setVaultMetrics] = useState({});

  // ==== Custom Hooks ====
  const {
    getUserVaults,
    getVaultDetails,
    getVaultAccessLog,
    getVaultMetrics,
    deleteVault,
    updateVaultSettings,
    getAccessRequests,
    approveAccessRequest,
    rejectAccessRequest,
    revokeAccess
  } = useDataVault();

  const {
    configurePrivacySettings,
    getPrivacyStatus
  } = usePrivacyLayer();

  const {
    getVaultRewards,
    claimRewards
  } = usePrivaToken();

  // ==== Effects ====
  /** Load user's vaults when the component mounts or userAddress changes */
  useEffect(() => {
    const loadVaults = async () => {
      if (!userAddress) {
        setError('User address is required to load vaults.');
        setIsLoading(false);
        return;
      }
      try {
        setIsLoading(true);
        const userVaults = await getUserVaults(userAddress);
        setVaults(userVaults);
        setError(null);
      } catch (err) {
        console.error('Failed to load vaults:', err);
        setError('Failed to load your data vaults. Please try again later.');
      } finally {
        setIsLoading(false);
      }
    };
    loadVaults();
  }, [userAddress, getUserVaults]);

  /** Load detailed information for the selected vault */
  useEffect(() => {
    const loadVaultDetails = async () => {
      if (!selectedVault) return;
      try {
        setIsLoading(true);
        const vaultDetails = await getVaultDetails(selectedVault.id);
        setSelectedVault(prevVault => ({ ...prevVault, ...vaultDetails }));
        const requests = await getAccessRequests(selectedVault.id);
        setAccessRequests(requests);
        const logs = await getVaultAccessLog(selectedVault.id);
        setVaultAccessLog(logs);
        const metrics = await getVaultMetrics(selectedVault.id);
        setVaultMetrics(metrics);
        setError(null);
      } catch (err) {
        console.error('Failed to load vault details:', err);
        setError('Failed to load vault details. Please try again later.');
      } finally {
        setIsLoading(false);
      }
    };
    loadVaultDetails();
  }, [selectedVault?.id, getVaultDetails, getAccessRequests, getVaultAccessLog, getVaultMetrics]);

  // ==== Derived State ====
  /** Filter, sort, and paginate vaults */
  const filteredVaults = useMemo(() => {
    return vaults
      .filter(vault => {
        if (!searchTerm) return true;
        const searchLower = searchTerm.toLowerCase();
        return (
          vault.name.toLowerCase().includes(searchLower) ||
          vault.description.toLowerCase().includes(searchLower) ||
          vault.tags.some(tag => tag.toLowerCase().includes(searchLower))
        );
      })
      .filter(vault => {
        if (filterType === 'all') return true;
        if (filterType === 'public') return vault.isPublic;
        if (filterType === 'private') return !vault.isPublic;
        if (filterType === 'shared') return vault.accessCount > 0;
        return true;
      })
      .sort((a, b) => {
        if (sortOrder === 'newest') return new Date(b.createdAt) - new Date(a.createdAt);
        if (sortOrder === 'oldest') return new Date(a.createdAt) - new Date(b.createdAt);
        if (sortOrder === 'name') return a.name.localeCompare(b.name);
        if (sortOrder === 'size') return b.size - a.size;
        if (sortOrder === 'activity') return b.lastAccessedAt - a.lastAccessedAt;
        return 0;
      });
  }, [vaults, searchTerm, filterType, sortOrder]);

  const paginatedVaults = useMemo(() => {
    const startIndex = (page - 1) * pageSize;
    return filteredVaults.slice(startIndex, startIndex + pageSize);
  }, [filteredVaults, page, pageSize]);

  const totalPages = useMemo(() => Math.ceil(filteredVaults.length / pageSize), [filteredVaults, pageSize]);

  // ==== Event Handlers ====
  const handleCreateVault = () => setShowUploadModal(true);

  const handleVaultClick = (vault) => {
    setSelectedVault(vault);
    setShowVaultDetailModal(true);
  };

  const handleDeleteVault = async () => {
    if (!selectedVault) return;
    try {
      setIsLoading(true);
      await deleteVault(selectedVault.id);
      setVaults(vaults.filter(vault => vault.id !== selectedVault.id));
      setShowDeleteConfirmModal(false);
      setShowVaultDetailModal(false);
      setSelectedVault(null);
      setError(null);
    } catch (err) {
      console.error('Failed to delete vault:', err);
      setError('Failed to delete vault. Please try again later.');
    } finally {
      setIsLoading(false);
    }
  };

  const handlePrivacySettingsUpdate = async (newSettings) => {
    if (!selectedVault) return;
    try {
      setIsLoading(true);
      await configurePrivacySettings(selectedVault.id, newSettings);
      setSelectedVault(prevVault => ({
        ...prevVault,
        privacySettings: newSettings
      }));
      setShowPrivacySettingsModal(false);
      setError(null);
    } catch (err) {
      console.error('Failed to update privacy settings:', err);
      setError('Failed to update privacy settings. Please try again later.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleApproveAccessRequest = async (requestId) => {
    try {
      setIsLoading(true);
      await approveAccessRequest(requestId);
      setAccessRequests(prevRequests =>
        prevRequests.map(req =>
          req.id === requestId ? { ...req, status: 'approved', updatedAt: new Date() } : req
        )
      );
      setError(null);
    } catch (err) {
      console.error('Failed to approve access request:', err);
      setError('Failed to approve access request. Please try again later.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleRejectAccessRequest = async (requestId) => {
    try {
      setIsLoading(true);
      await rejectAccessRequest(requestId);
      setAccessRequests(prevRequests =>
        prevRequests.map(req =>
          req.id === requestId ? { ...req, status: 'rejected', updatedAt: new Date() } : req
        )
      );
      setError(null);
    } catch (err) {
      console.error('Failed to reject access request:', err);
      setError('Failed to reject access request. Please try again later.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleRevokeAccess = async (accessId) => {
    try {
      setIsLoading(true);
      await revokeAccess(accessId);
      setSelectedVault(prevVault => ({
        ...prevVault,
        accessList: prevVault.accessList.filter(access => access.id !== accessId)
      }));
      setError(null);
    } catch (err) {
      console.error('Failed to revoke access:', err);
      setError('Failed to revoke access. Please try again later.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleClaimRewards = async (vaultId) => {
    try {
      setIsLoading(true);
      await claimRewards(vaultId);
      const updatedVault = await getVaultDetails(vaultId);
      setSelectedVault(updatedVault);
      setVaults(prevVaults =>
        prevVaults.map(vault =>
          vault.id === vaultId ? { ...vault, ...updatedVault } : vault
        )
      );
      setError(null);
    } catch (err) {
      console.error('Failed to claim rewards:', err);
      setError('Failed to claim rewards. Please try again later.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleUpdateVaultSettings = async (newSettings) => {
    if (!selectedVault) return;
    try {
      setIsLoading(true);
      await updateVaultSettings(selectedVault.id, newSettings);
      setSelectedVault(prevVault => ({ ...prevVault, ...newSettings }));
      setVaults(prevVaults =>
        prevVaults.map(vault =>
          vault.id === selectedVault.id ? { ...vault, ...newSettings } : vault
        )
      );
      setError(null);
    } catch (err) {
      console.error('Failed to update vault settings:', err);
      setError('Failed to update vault settings. Please try again later.');
    } finally {
      setIsLoading(false);
    }
  };

  // ==== Helper Functions ====
  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  };

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'approved': return 'text-green-500';
      case 'rejected': return 'text-red-500';
      case 'pending': return 'text-yellow-500';
      case 'expired': return 'text-gray-500';
      default: return 'text-gray-500';
    }
  };

  const getPrivacyTechnologyIcon = (technology) => {
    switch (technology) {
      case 'differential-privacy': return <Shield className="w-4 h-4" />;
      case 'federated-learning': return <Activity className="w-4 h-4" />;
      case 'secure-mpc': return <Users className="w-4 h-4" />;
      case 'zero-knowledge-proofs': return <ZeroKnowledge className="w-4 h-4" />;
      default: return <Lock className="w-4 h-4" />;
    }
  };

  // ==== Render Helpers ====
  const renderEmptyState = () => (
    <div className="text-center py-16">
      <Database className="mx-auto h-12 w-12 text-gray-400" />
      <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No data vaults</h3>
      <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
        Get started by creating your first data vault.
      </p>
      <div className="mt-6">
        <Button
          variant="primary"
          onClick={handleCreateVault}
          icon={<Plus className="w-4 h-4" />}
        >
          Create New Vault
        </Button>
      </div>
    </div>
  );

  const renderVaultGrid = () => (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
      {paginatedVaults.map((vault) => (
        <DataVaultCard
          key={vault.id}
          title={vault.name}
          subtitle={vault.description}
          totalRecords={vault.recordCount}
          lastUpdated={formatDate(vault.updatedAt)}
          onClick={() => handleVaultClick(vault)}
          className="cursor-pointer"
        >
          <div className="mb-3">
            {vault.tags.length > 0 && (
              <div className="flex flex-wrap gap-1 mt-2">
                {vault.tags.slice(0, 3).map((tag) => (
                  <span key={tag} className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-800 dark:text-blue-100">
                    {tag}
                  </span>
                ))}
                {vault.tags.length > 3 && (
                  <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300">
                    +{vault.tags.length - 3}
                  </span>
                )}
              </div>
            )}
          </div>
          <div className="flex items-center justify-between text-sm">
            <div className="flex items-center">
              <Database className="w-4 h-4 text-gray-500 mr-1" />
              <span className="text-gray-500">{formatFileSize(vault.size)}</span>
            </div>
            <div className="flex items-center gap-2">
              {vault.privacyTechnologies?.map((tech) => (
                <span key={tech} className="text-gray-500" title={tech}>
                  {getPrivacyTechnologyIcon(tech)}
                </span>
              ))}
              {vault.isPublic ? (
                <Eye className="w-4 h-4 text-gray-500" title="Public" />
              ) : (
                <EyeOff className="w-4 h-4 text-gray-500" title="Private" />
              )}
              {vault.accessCount > 0 && (
                <span className="flex items-center text-gray-500" title={`${vault.accessCount} access grants`}>
                  <Users className="w-4 h-4 mr-1" />
                  {vault.accessCount}
                </span>
              )}
            </div>
          </div>
        </DataVaultCard>
      ))}
    </div>
  );

  const renderPagination = () => (
    <div className="mt-4 flex items-center justify-between">
      <div className="flex items-center text-gray-500 dark:text-gray-400 text-sm">
        Showing <span className="font-medium mx-1">{(page - 1) * pageSize + 1}</span>
        to <span className="font-medium mx-1">{Math.min(page * pageSize, filteredVaults.length)}</span>
        of <span className="font-medium mx-1">{filteredVaults.length}</span> vaults
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

  // ==== Main UI ====
  return (
    <div className={`vault-management-container ${className}`} {...props}>
      {/* Header */}
      <div className="mb-6 flex flex-col sm:flex-row sm:justify-between sm:items-center space-y-4 sm:space-y-0">
        <div>
          <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Data Vaults</h2>
          <p className="text-sm text-gray-500 dark:text-gray-400">
            Manage your secure data vaults with privacy-preserving analytics
          </p>
        </div>
        <Button
          variant="primary"
          onClick={handleCreateVault}
          icon={<Plus className="w-4 h-4" />}
        >
          Create New Vault
        </Button>
      </div>

      {/* Error Display */}
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
      <div className="mb-6 space-y-4 sm:space-y-0 sm:flex sm:items-center sm:justify-between">
        <div className="relative flex items-center">
          <Search className="absolute left-3 h-5 w-5 text-gray-400" />
          <input
            type="text"
            placeholder="Search vaults..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pl-10 pr-3 py-2 w-full sm:w-64 border border-gray-300 dark:border-gray-700 rounded-md text-gray-900 dark:text-white bg-white dark:bg-gray-800 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
        </div>
        <div className="flex items-center space-x-3">
          <div className="relative">
            <label className="sr-only">Filter</label>
            <div className="flex items-center">
              <span className="mr-2 text-sm text-gray-500 dark:text-gray-400">
                <Filter className="h-4 w-4" />
              </span>
              <select
                value={filterType}
                onChange={(e) => setFilterType(e.target.value)}
                className="appearance-none bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-md py-2 pl-3 pr-8 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="all">All Vaults</option>
                <option value="public">Public Vaults</option>
                <option value="private">Private Vaults</option>
                <option value="shared">Shared Vaults</option>
              </select>
              <ChevronDown className="absolute right-2 h-4 w-4 text-gray-700 dark:text-gray-300 pointer-events-none" />
            </div>
          </div>
          <div className="relative">
            <label className="sr-only">Sort</label>
            <div className="flex items-center">
              <span className="mr-2 text-sm text-gray-500 dark:text-gray-400">Sort:</span>
              <select
                value={sortOrder}
                onChange={(e) => setSortOrder(e.target.value)}
                className="appearance-none bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-md py-2 pl-3 pr-8 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="newest">Newest</option>
                <option value="oldest">Oldest</option>
                <option value="name">Name</option>
                <option value="size">Size</option>
                <option value="activity">Recent Activity</option>
              </select>
              <ChevronDown className="absolute right-2 h-4 w-4 text-gray-700 dark:text-gray-300 pointer-events-none" />
            </div>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="mb-6">
        {isLoading && !vaults.length ? (
          <div className="py-16 flex justify-center">
            <div className="animate-spin rounded-full h-10 w-10 border-4 border-blue-500 border-t-transparent"></div>
          </div>
        ) : vaults.length === 0 ? (
          renderEmptyState()
        ) : (
          <>
            {renderVaultGrid()}
            {totalPages > 1 && renderPagination()}
          </>
        )}
      </div>

      {/* Modals */}
      <Modal
        isOpen={showUploadModal}
        onClose={() => setShowUploadModal(false)}
        title="Create Data Vault"
        description="Upload data and configure privacy settings"
        size="large"
      >
        <DataUpload
          onUploadComplete={() => {
            setShowUploadModal(false);
            getUserVaults(userAddress).then(setVaults);
          }}
          onUploadError={(errorMsg) => {
            setError(errorMsg);
            setShowUploadModal(false);
          }}
          onCancel={() => setShowUploadModal(false)}
          createNewVault={true}
          defaultPrivacySettings={{
            enableDifferentialPrivacy: true,
            enableFederatedLearning: false,
            enableSecureMpc: true,
            enableZkp: true,
            privacyBudget: 1.0
          }}
        />
      </Modal>

      <Modal
        isOpen={showVaultDetailModal}
        onClose={() => {
          setShowVaultDetailModal(false);
          setSelectedVault(null);
        }}
        title={selectedVault?.name}
        size="large"
        footer={
          <div className="flex justify-between">
            <Button
              variant="danger"
              onClick={() => {
                setShowVaultDetailModal(false);
                setShowDeleteConfirmModal(true);
              }}
              icon={<Trash className="w-4 h-4" />}
            >
              Delete Vault
            </Button>
            <div className="flex space-x-3">
              <Button
                variant="secondary"
                onClick={() => setShowVaultDetailModal(false)}
              >
                Close
              </Button>
              <Button
                variant="primary"
                onClick={() => {
                  setShowVaultDetailModal(false);
                  setShowPrivacySettingsModal(true);
                }}
                icon={<Shield className="w-4 h-4" />}
              >
                Privacy Settings
              </Button>
            </div>
          </div>
        }
      >
        {selectedVault && (
          <div className="space-y-6">
            <div className="bg-gray-50 dark:bg-gray-800 p-4 rounded-lg">
              <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">Vault Information</h3>
              <dl className="grid grid-cols-1 md:grid-cols-2 gap-x-4 gap-y-2">
                <div>
                  <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">ID</dt>
                  <dd className="mt-1 text-sm text-gray-900 dark:text-white">{selectedVault.id}</dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Created</dt>
                  <dd className="mt-1 text-sm text-gray-900 dark:text-white">{formatDate(selectedVault.createdAt)}</dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Last Updated</dt>
                  <dd className="mt-1 text-sm text-gray-900 dark:text-white">{formatDate(selectedVault.updatedAt)}</dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Size</dt>
                  <dd className="mt-1 text-sm text-gray-900 dark:text-white">{formatFileSize(selectedVault.size)}</dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Records</dt>
                  <dd className="mt-1 text-sm text-gray-900 dark:text-white">{selectedVault.recordCount} records</dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Visibility</dt>
                  <dd className="mt-1 text-sm text-gray-900 dark:text-white">
                    {selectedVault.isPublic ? 'Public' : 'Private'}
                  </dd>
                </div>
                <div className="md:col-span-2">
                  <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Description</dt>
                  <dd className="mt-1 text-sm text-gray-900 dark:text-white">{selectedVault.description}</dd>
                </div>
                <div className="md:col-span-2">
                  <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Tags</dt>
                  <dd className="mt-1 flex flex-wrap gap-1">
                    {selectedVault.tags.map(tag => (
                      <span key={tag} className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-800 dark:text-blue-100">
                        {tag}
                      </span>
                    ))}
                  </dd>
                </div>
              </dl>
            </div>

            <div>
              <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">Privacy Technologies</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {[
                  { id: 'differential-privacy', title: 'Differential Privacy', enabled: selectedVault.privacySettings?.enableDifferentialPrivacy },
                  { id: 'federated-learning', title: 'Federated Learning', enabled: selectedVault.privacySettings?.enableFederatedLearning },
                  { id: 'secure-mpc', title: 'Secure MPC', enabled: selectedVault.privacySettings?.enableSecureMpc },
                  { id: 'zero-knowledge-proofs', title: 'Zero-Knowledge Proofs', enabled: selectedVault.privacySettings?.enableZkp }
                ].map(tech => (
                  <div key={tech.id} className={`p-4 rounded-lg border ${tech.enabled ? 'border-blue-200 bg-blue-50 dark:border-blue-800 dark:bg-blue-900/20' : 'border-gray-200 dark:border-gray-700'}`}>
                    <div className="flex items-start">
                      <div className={`flex-shrink-0 h-10 w-10 rounded-full flex items-center justify-center ${tech.enabled ? 'bg-blue-100 dark:bg-blue-800' : 'bg-gray-100 dark:bg-gray-800'}`}>
                        {getPrivacyTechnologyIcon(tech.id)}
                      </div>
                      <div className="ml-4">
                        <h4 className="text-base font-medium text-gray-900 dark:text-white">{tech.title}</h4>
                        <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">{tech.enabled ? 'Enabled' : 'Not enabled'}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div>
              <div className="flex justify-between items-center mb-2">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white">Access Controls</h3>
                <Button
                  variant="secondary"
                  size="small"
                  onClick={() => {
                    setShowVaultDetailModal(false);
                    setShowAccessControlModal(true);
                  }}
                  icon={<Edit className="w-4 h-4" />}
                >
                  Manage Access
                </Button>
              </div>
              {selectedVault.accessList?.length > 0 ? (
                <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                  <thead className="bg-gray-50 dark:bg-gray-800">
                    <tr>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">User</th>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Access Level</th>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Granted</th>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Expires</th>
                      <th className="px-4 py-2"></th>
                    </tr>
                  </thead>
                  <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-700">
                    {selectedVault.accessList.map(access => (
                      <tr key={access.id}>
                        <td className="px-4 py-2 text-sm text-gray-900 dark:text-white">{access.user}</td>
                        <td className="px-4 py-2 text-sm text-gray-900 dark:text-white">{access.accessLevel}</td>
                        <td className="px-4 py-2 text-sm text-gray-500 dark:text-gray-400">{formatDate(access.grantedAt)}</td>
                        <td className="px-4 py-2 text-sm text-gray-500 dark:text-gray-400">{access.expiresAt ? formatDate(access.expiresAt) : 'Never'}</td>
                        <td className="px-4 py-2 text-right text-sm font-medium">
                          <button
                            onClick={() => handleRevokeAccess(access.id)}
                            className="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300"
                          >
                            Revoke
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <p className="text-center p-4 border border-gray-200 dark:border-gray-700 rounded-lg text-sm text-gray-500 dark:text-gray-400">
                  No access has been granted to this vault
                </p>
              )}
            </div>

            {accessRequests.length > 0 && (
              <div>
                <div className="flex justify-between items-center mb-2">
                  <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                    Access Requests <span className="ml-2 text-sm bg-yellow-100 text-yellow-800 dark:bg-yellow-800 dark:text-yellow-100 px-2 py-0.5 rounded-full">{accessRequests.filter(r => r.status === 'pending').length}</span>
                  </h3>
                  <Button
                    variant="secondary"
                    size="small"
                    onClick={() => {
                      setShowVaultDetailModal(false);
                      setShowAccessRequestsModal(true);
                    }}
                    icon={<ExternalLink className="w-4 h-4" />}
                  >
                    View All
                  </Button>
                </div>
                <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                  <thead className="bg-gray-50 dark:bg-gray-800">
                    <tr>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Requestor</th>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Purpose</th>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Status</th>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Requested</th>
                      <th className="px-4 py-2"></th>
                    </tr>
                  </thead>
                  <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-700">
                    {accessRequests.filter(req => req.status === 'pending').slice(0, 3).map(request => (
                      <tr key={request.id}>
                        <td className="px-4 py-2 text-sm text-gray-900 dark:text-white">{request.requestor}</td>
                        <td className="px-4 py-2 text-sm text-gray-900 dark:text-white max-w-xs truncate">{request.purpose}</td>
                        <td className="px-4 py-2 text-sm">
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(request.status)} bg-opacity-10`}>
                            {request.status.charAt(0).toUpperCase() + request.status.slice(1)}
                          </span>
                        </td>
                        <td className="px-4 py-2 text-sm text-gray-500 dark:text-gray-400">{formatDate(request.createdAt)}</td>
                        <td className="px-4 py-2 text-right text-sm font-medium">
                          <div className="flex justify-end space-x-2">
                            <button
                              onClick={() => handleRejectAccessRequest(request.id)}
                              className="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300"
                            >
                              Reject
                            </button>
                            <button
                              onClick={() => handleApproveAccessRequest(request.id)}
                              className="text-green-600 hover:text-green-900 dark:text-green-400 dark:hover:text-green-300"
                            >
                              Approve
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {Object.keys(vaultMetrics).length > 0 && (
              <div>
                <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">Usage Metrics</h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
                    <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400">Access Requests</h4>
                    <p className="text-2xl font-bold text-gray-900 dark:text-white">{vaultMetrics.accessRequestCount}</p>
                  </div>
                  <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
                    <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400">Data Usage</h4>
                    <p className="text-2xl font-bold text-gray-900 dark:text-white">{vaultMetrics.usageCount}</p>
                  </div>
                  <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
                    <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400">PRIVA Rewards</h4>
                    <p className="text-2xl font-bold text-gray-900 dark:text-white">{vaultMetrics.privaRewards}</p>
                    {vaultMetrics.claimableRewards > 0 && (
                      <button
                        onClick={() => handleClaimRewards(selectedVault.id)}
                        className="mt-1 text-xs text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300"
                      >
                        Claim {vaultMetrics.claimableRewards} PRIVA
                      </button>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </Modal>

      <PrivacySettingsModal
        isOpen={showPrivacySettingsModal}
        onClose={() => setShowPrivacySettingsModal(false)}
        settings={[
          {
            id: 'enableDifferentialPrivacy',
            title: 'Differential Privacy',
            description: 'Adds mathematical noise to protect individual data points.',
            enabled: selectedVault?.privacySettings?.enableDifferentialPrivacy || false
          },
          {
            id: 'enableFederatedLearning',
            title: 'Federated Learning',
            description: 'Allows model training without centralizing sensitive data.',
            enabled: selectedVault?.privacySettings?.enableFederatedLearning || false
          },
          {
            id: 'enableSecureMpc',
            title: 'Secure Multi-Party Computation',
            description: 'Enables encrypted computations without exposing inputs.',
            enabled: selectedVault?.privacySettings?.enableSecureMpc || false
          },
          {
            id: 'enableZkp',
            title: 'Zero-Knowledge Proofs',
            description: 'Verifies data properties without revealing data.',
            enabled: selectedVault?.privacySettings?.enableZkp || false
          }
        ]}
        onSettingsChange={(settingId, enabled) => {
          if (selectedVault) {
            const newSettings = { ...selectedVault.privacySettings, [settingId]: enabled };
            handlePrivacySettingsUpdate(newSettings);
          }
        }}
      />

      <Modal
        isOpen={showAccessControlModal}
        onClose={() => setShowAccessControlModal(false)}
        title="Manage Access Controls"
        size="large"
      >
        {selectedVault && (
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">Current Access</h3>
              {selectedVault.accessList?.length > 0 ? (
                <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                  <thead className="bg-gray-50 dark:bg-gray-800">
                    <tr>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">User</th>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Access Level</th>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Granted</th>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Expires</th>
                      <th className="px-4 py-2"></th>
                    </tr>
                  </thead>
                  <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-700">
                    {selectedVault.accessList.map(access => (
                      <tr key={access.id}>
                        <td className="px-4 py-2 text-sm text-gray-900 dark:text-white">{access.user}</td>
                        <td className="px-4 py-2 text-sm text-gray-900 dark:text-white">{access.accessLevel}</td>
                        <td className="px-4 py-2 text-sm text-gray-500 dark:text-gray-400">{formatDate(access.grantedAt)}</td>
                        <td className="px-4 py-2 text-sm text-gray-500 dark:text-gray-400">{access.expiresAt ? formatDate(access.expiresAt) : 'Never'}</td>
                        <td className="px-4 py-2 text-right text-sm font-medium">
                          <button
                            onClick={() => handleRevokeAccess(access.id)}
                            className="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300"
                          >
                            Revoke
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <p className="text-center p-4 border border-gray-200 dark:border-gray-700 rounded-lg text-sm text-gray-500 dark:text-gray-400">
                  No access has been granted to this vault
                </p>
              )}
            </div>

            <div>
              <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">Pending Requests</h3>
              {accessRequests.filter(req => req.status === 'pending').length > 0 ? (
                <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                  <thead className="bg-gray-50 dark:bg-gray-800">
                    <tr>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Requestor</th>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Purpose</th>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Requested</th>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Access Level</th>
                      <th className="px-4 py-2"></th>
                    </tr>
                  </thead>
                  <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-700">
                    {accessRequests.filter(req => req.status === 'pending').map(request => (
                      <tr key={request.id}>
                        <td className="px-4 py-2 text-sm text-gray-900 dark:text-white">{request.requestor}</td>
                        <td className="px-4 py-2 text-sm text-gray-900 dark:text-white max-w-xs truncate">{request.purpose}</td>
                        <td className="px-4 py-2 text-sm text-gray-500 dark:text-gray-400">{formatDate(request.createdAt)}</td>
                        <td className="px-4 py-2 text-sm text-gray-900 dark:text-white">{request.accessLevel}</td>
                        <td className="px-4 py-2 text-right text-sm font-medium">
                          <div className="flex justify-end space-x-2">
                            <button
                              onClick={() => handleRejectAccessRequest(request.id)}
                              className="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300"
                            >
                              Reject
                            </button>
                            <button
                              onClick={() => handleApproveAccessRequest(request.id)}
                              className="text-green-600 hover:text-green-900 dark:text-green-400 dark:hover:text-green-300"
                            >
                              Approve
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <p className="text-center p-4 border border-gray-200 dark:border-gray-700 rounded-lg text-sm text-gray-500 dark:text-gray-400">
                  No pending access requests
                </p>
              )}
            </div>

            <div>
              <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">Visibility Settings</h3>
              <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
                <div className="flex items-start mb-4">
                  <input
                    id="isPublic"
                    type="checkbox"
                    checked={selectedVault.isPublic}
                    onChange={(e) => handleUpdateVaultSettings({ isPublic: e.target.checked })}
                    className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded dark:border-gray-700 dark:bg-gray-700"
                  />
                  <div className="ml-3 text-sm">
                    <label htmlFor="isPublic" className="font-medium text-gray-900 dark:text-white">Make data discoverable</label>
                    <p className="text-gray-500 dark:text-gray-400">Allow other users to discover this vault in the marketplace (access still requires approval).</p>
                  </div>
                </div>
                <div>
                  <label htmlFor="accessRequestSettings" className="block text-sm font-medium text-gray-900 dark:text-white">Access Request Handling</label>
                  <select
                    id="accessRequestSettings"
                    value={selectedVault.accessRequestSettings || 'manual'}
                    onChange={(e) => handleUpdateVaultSettings({ accessRequestSettings: e.target.value })}
                    className="mt-1 block w-full pl-3 pr-10 py-2 text-base border-gray-300 dark:border-gray-700 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm rounded-md dark:bg-gray-800 dark:text-white"
                  >
                    <option value="manual">Manual Review</option>
                    <option value="auto-trusted">Auto-approve Trusted Users</option>
                    <option value="auto-all">Auto-approve All</option>
                    <option value="closed">Closed</option>
                  </select>
                </div>
              </div>
            </div>
          </div>
        )}
      </Modal>

      <Modal
        isOpen={showAccessRequestsModal}
        onClose={() => setShowAccessRequestsModal(false)}
        title="Access Requests"
        size="large"
      >
        {selectedVault && (
          <div className="space-y-6">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">All Access Requests</h3>
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead className="bg-gray-50 dark:bg-gray-800">
                <tr>
                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Requestor</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Purpose</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Status</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Requested</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Updated</th>
                  <th className="px-4 py-2"></th>
                </tr>
              </thead>
              <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-700">
                {accessRequests.map(request => (
                  <tr key={request.id}>
                    <td className="px-4 py-2 text-sm text-gray-900 dark:text-white">{request.requestor}</td>
                    <td className="px-4 py-2 text-sm text-gray-900 dark:text-white max-w-xs truncate">{request.purpose}</td>
                    <td className="px-4 py-2 text-sm">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(request.status)} bg-opacity-10`}>
                        {request.status.charAt(0).toUpperCase() + request.status.slice(1)}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-sm text-gray-500 dark:text-gray-400">{formatDate(request.createdAt)}</td>
                    <td className="px-4 py-2 text-sm text-gray-500 dark:text-gray-400">{formatDate(request.updatedAt) || 'N/A'}</td>
                    <td className="px-4 py-2 text-right text-sm font-medium">
                      {request.status === 'pending' && (
                        <div className="flex justify-end space-x-2">
                          <button
                            onClick={() => handleRejectAccessRequest(request.id)}
                            className="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300"
                          >
                            Reject
                          </button>
                          <button
                            onClick={() => handleApproveAccessRequest(request.id)}
                            className="text-green-600 hover:text-green-900 dark:text-green-400 dark:hover:text-green-300"
                          >
                            Approve
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Modal>

      <Modal
        isOpen={showDeleteConfirmModal}
        onClose={() => setShowDeleteConfirmModal(false)}
        title="Delete Data Vault"
        variant="danger"
      >
        <div className="space-y-4">
          <div className="bg-red-50 dark:bg-red-900/20 p-4 rounded-lg">
            <div className="flex">
              <AlertTriangle className="h-6 w-6 text-red-600 dark:text-red-400" />
              <div className="ml-3">
                <h3 className="text-sm font-medium text-red-800 dark:text-red-200">Warning</h3>
                <p className="mt-1 text-sm text-red-700 dark:text-red-300">
                  Deleting this vault will permanently remove all data and revoke all access. This action cannot be undone.
                </p>
              </div>
            </div>
          </div>
          <p className="text-sm text-gray-700 dark:text-gray-300">
            Are you sure you want to delete <span className="font-medium">{selectedVault?.name}</span>?
          </p>
          <div className="flex justify-end space-x-3">
            <Button variant="secondary" onClick={() => setShowDeleteConfirmModal(false)}>Cancel</Button>
            <Button variant="danger" onClick={handleDeleteVault} isLoading={isLoading}>Delete Permanently</Button>
          </div>
        </div>
      </Modal>
    </div>
  );
};

VaultManagement.propTypes = {
  userAddress: PropTypes.string.isRequired,
  className: PropTypes.string,
};

export default VaultManagement;
