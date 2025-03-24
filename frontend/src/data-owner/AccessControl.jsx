/**
 * AccessControl Component
 * 
 * A comprehensive component for managing privacy-preserving access controls
 * for data vaults in the PrivaSight platform.
 */

import React, { useState, useEffect, useMemo } from 'react';
import PropTypes from 'prop-types';
import { useDataVault } from '../../hooks/useDataVault';
import { usePrivacyLayer } from '../../hooks/usePrivacyLayer';

// Icons
import {
  Shield,
  Lock,
  Key,
  User,
  Users,
  Clock,
  Calendar,
  CheckCircle,
  AlertTriangle,
  XCircle,
  Info,
  MoreVertical,
  Search,
  Filter,
  Plus,
  Eye,
  EyeOff,
  FileText,
  RefreshCw,
  Database,
  Share,
  UserPlus,
  UserMinus,
  Settings,
  ChevronDown,
  ExternalLink,
  ZeroKnowledge
} from '../icons';

// Components
import Button, { IconButton } from '../common/Button';
import Card from '../common/Card';
import Modal from '../common/Modal';

const AccessControl = ({
  vaultId,
  onUpdated,
  className = '',
  ...props
}) => {
  // ==== State Management ====
  const [vaultInfo, setVaultInfo] = useState(null);
  const [accessList, setAccessList] = useState([]);
  const [accessRequestList, setAccessRequestList] = useState([]);
  const [accessHistoryList, setAccessHistoryList] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);

  // Filters and search
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [typeFilter, setTypeFilter] = useState('all');
  const [sortBy, setSortBy] = useState('newest');

  // Modal states
  const [showAccessDetailModal, setShowAccessDetailModal] = useState(false);
  const [showAddAccessModal, setShowAddAccessModal] = useState(false);
  const [showRevokeConfirmModal, setShowRevokeConfirmModal] = useState(false);
  const [selectedAccess, setSelectedAccess] = useState(null);
  const [showPrivacySettingsModal, setShowPrivacySettingsModal] = useState(false);

  // Form states
  const [newAccessForm, setNewAccessForm] = useState({
    userAddress: '',
    accessLevel: 'read',
    expiresAt: '',
    purpose: '',
    allowReExport: false,
    allowDerivedData: false,
    privacyConstraints: {
      differentialPrivacy: true,
      secureMpc: false,
      zkp: true,
      federatedLearning: false,
      privacyBudget: 1.0
    }
  });

  // ==== Custom Hooks ====
  const {
    getVaultDetails,
    getVaultAccessList,
    getAccessRequests,
    getAccessHistory,
    grantAccess,
    revokeAccess,
    approveAccessRequest,
    rejectAccessRequest,
    modifyAccessSettings,
    getAccessDetails
  } = useDataVault();

  const {
    configurePrivacySettings,
    getPrivacyStatus,
    verifyZkpAccess,
    generateAccessProof
  } = usePrivacyLayer();

  // ==== Effects ====
  // Load vault details and access information
  useEffect(() => {
    const loadVaultData = async () => {
      if (!vaultId) return;

      try {
        setIsLoading(true);
        setError(null);

        const vault = await getVaultDetails(vaultId);
        setVaultInfo(vault);

        const access = await getVaultAccessList(vaultId);
        setAccessList(access);

        const requests = await getAccessRequests(vaultId);
        setAccessRequestList(requests);

        const history = await getAccessHistory(vaultId);
        setAccessHistoryList(history);
      } catch (err) {
        console.error('Failed to load vault access data:', err);
        setError('Failed to load access information. Please try again.');
      } finally {
        setIsLoading(false);
      }
    };

    loadVaultData();
  }, [vaultId, getVaultDetails, getVaultAccessList, getAccessRequests, getAccessHistory]);

  // Load selected access details
  useEffect(() => {
    const loadAccessDetails = async () => {
      if (!selectedAccess?.id) return;

      try {
        setIsLoading(true);
        const accessDetails = await getAccessDetails(selectedAccess.id);
        setSelectedAccess({ ...selectedAccess, ...accessDetails });
      } catch (err) {
        console.error('Failed to load access details:', err);
        setError('Failed to load access details. Please try again.');
      } finally {
        setIsLoading(false);
      }
    };

    if (selectedAccess && showAccessDetailModal) {
      loadAccessDetails();
    }
  }, [selectedAccess?.id, showAccessDetailModal, getAccessDetails]);

  // ==== Derived State ====
  const filteredAccessList = useMemo(() => {
    return accessList
      .filter(access => {
        if (searchTerm) {
          const searchLower = searchTerm.toLowerCase();
          return (
            access.user.toLowerCase().includes(searchLower) ||
            access.accessLevel.toLowerCase().includes(searchLower) ||
            (access.purpose && access.purpose.toLowerCase().includes(searchLower))
          );
        }
        return true;
      })
      .filter(access => statusFilter === 'all' ? true : access.status === statusFilter)
      .filter(access => typeFilter === 'all' ? true : access.accessLevel === typeFilter)
      .sort((a, b) => {
        if (sortBy === 'newest') return new Date(b.grantedAt) - new Date(a.grantedAt);
        if (sortBy === 'oldest') return new Date(a.grantedAt) - new Date(b.grantedAt);
        if (sortBy === 'user') return a.user.localeCompare(b.user);
        if (sortBy === 'expiry') {
          if (!a.expiresAt && !b.expiresAt) return 0;
          if (!a.expiresAt) return 1;
          if (!b.expiresAt) return -1;
          return new Date(a.expiresAt) - new Date(b.expiresAt);
        }
        if (sortBy === 'level') {
          const levels = { admin: 4, write: 3, compute: 2, read: 1 };
          return (levels[b.accessLevel] || 0) - (levels[a.accessLevel] || 0);
        }
        return 0;
      });
  }, [accessList, searchTerm, statusFilter, typeFilter, sortBy]);

  const filteredAccessRequests = useMemo(() => {
    return accessRequestList
      .filter(request => statusFilter === 'all' ? true : request.status === statusFilter)
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  }, [accessRequestList, statusFilter]);

  // ==== Event Handlers ====
  const handleAddAccess = async () => {
    try {
      setIsLoading(true);
      setError(null);

      let accessProof = null;
      if (newAccessForm.privacyConstraints.zkp) {
        accessProof = await generateAccessProof(vaultId, newAccessForm.userAddress);
      }

      await grantAccess(vaultId, {
        ...newAccessForm,
        expiresAt: newAccessForm.expiresAt || null,
        accessProof
      });

      const updatedAccess = await getVaultAccessList(vaultId);
      setAccessList(updatedAccess);

      setShowAddAccessModal(false);
      setNewAccessForm({
        userAddress: '',
        accessLevel: 'read',
        expiresAt: '',
        purpose: '',
        allowReExport: false,
        allowDerivedData: false,
        privacyConstraints: {
          differentialPrivacy: true,
          secureMpc: false,
          zkp: true,
          federatedLearning: false,
          privacyBudget: 1.0
        }
      });

      if (onUpdated) onUpdated();
    } catch (err) {
      console.error('Failed to add access:', err);
      setError('Failed to grant access. Please check the address and try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleRevokeAccess = async () => {
    if (!selectedAccess) return;

    try {
      setIsLoading(true);
      setError(null);

      await revokeAccess(selectedAccess.id);

      const updatedAccess = await getVaultAccessList(vaultId);
      setAccessList(updatedAccess);

      setShowRevokeConfirmModal(false);
      setShowAccessDetailModal(false);
      setSelectedAccess(null);

      if (onUpdated) onUpdated();
    } catch (err) {
      console.error('Failed to revoke access:', err);
      setError('Failed to revoke access. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleApproveRequest = async (requestId) => {
    try {
      setIsLoading(true);
      setError(null);

      await approveAccessRequest(requestId);

      const updatedRequests = await getAccessRequests(vaultId);
      setAccessRequestList(updatedRequests);

      const updatedAccess = await getVaultAccessList(vaultId);
      setAccessList(updatedAccess);

      if (onUpdated) onUpdated();
    } catch (err) {
      console.error('Failed to approve request:', err);
      setError('Failed to approve access request. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleRejectRequest = async (requestId) => {
    try {
      setIsLoading(true);
      setError(null);

      await rejectAccessRequest(requestId);

      const updatedRequests = await getAccessRequests(vaultId);
      setAccessRequestList(updatedRequests);

      if (onUpdated) onUpdated();
    } catch (err) {
      console.error('Failed to reject request:', err);
      setError('Failed to reject access request. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleModifyAccessLevel = async (accessId, newLevel) => {
    try {
      setIsLoading(true);
      setError(null);

      await modifyAccessSettings(accessId, { accessLevel: newLevel });

      const updatedAccess = await getVaultAccessList(vaultId);
      setAccessList(updatedAccess);

      if (selectedAccess && selectedAccess.id === accessId) {
        setSelectedAccess({ ...selectedAccess, accessLevel: newLevel });
      }

      if (onUpdated) onUpdated();
    } catch (err) {
      console.error('Failed to modify access level:', err);
      setError('Failed to modify access level. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleUpdateAccessSettings = async (settings) => {
    if (!selectedAccess) return;

    try {
      setIsLoading(true);
      setError(null);

      await modifyAccessSettings(selectedAccess.id, settings);

      const updatedAccess = await getVaultAccessList(vaultId);
      setAccessList(updatedAccess);

      setSelectedAccess({ ...selectedAccess, ...settings });

      if (onUpdated) onUpdated();
    } catch (err) {
      console.error('Failed to update access settings:', err);
      setError('Failed to update access settings. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  // ==== Helper Functions ====
  const formatDate = (date) => {
    if (!date) return 'Never';
    return new Date(date).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  };

  const formatDateTime = (date) => {
    if (!date) return 'N/A';
    return new Date(date).toLocaleString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  };

  const getAccessLevelBadge = (level) => {
    const styles = {
      admin: 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200',
      write: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
      read: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
      compute: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200'
    };
    return (
      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${styles[level] || 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200'}`}>
        {level.charAt(0).toUpperCase() + level.slice(1)}
      </span>
    );
  };

  const getStatusBadge = (status) => {
    const styles = {
      active: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
      expired: 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200',
      revoked: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
      pending: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
      approved: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
      rejected: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
    };
    return (
      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${styles[status] || 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200'}`}>
        {status.charAt(0).toUpperCase() + status.slice(1)}
      </span>
    );
  };

  const shortenAddress = (address, chars = 4) => {
    if (!address) return '';
    return `${address.substring(0, chars + 2)}...${address.substring(address.length - chars)}`;
  };

  const getPrivacyIcon = (technology) => {
    switch (technology) {
      case 'differentialPrivacy': return <Shield className="w-4 h-4" title="Differential Privacy" />;
      case 'secureMpc': return <Users className="w-4 h-4" title="Secure Multi-Party Computation" />;
      case 'zkp': return <ZeroKnowledge className="w-4 h-4" title="Zero-Knowledge Proofs" />;
      case 'federatedLearning': return <Database className="w-4 h-4" title="Federated Learning" />;
      default: return <Lock className="w-4 h-4" title="Privacy Protection" />;
    }
  };

  // ==== Render Helpers ====
  const renderEmptyState = () => (
    <div className="text-center py-12">
      <div className="mx-auto h-12 w-12 text-gray-400">
        <Key className="h-12 w-12" />
      </div>
      <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No access granted</h3>
      <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">No users currently have access to this data vault.</p>
      <div className="mt-6">
        <Button variant="primary" onClick={() => setShowAddAccessModal(true)} icon={<UserPlus className="w-4 h-4" />}>
          Grant Access
        </Button>
      </div>
    </div>
  );

  // ==== Main Render ====
  return (
    <div className={`access-control-container ${className}`} {...props}>
      {/* Header */}
      <div className="mb-6 flex flex-col sm:flex-row sm:justify-between sm:items-center space-y-4 sm:space-y-0">
        <div>
          <h2 className="text-xl font-bold text-gray-900 dark:text-white">Access Control</h2>
          <p className="text-sm text-gray-500 dark:text-gray-400">Manage privacy-preserving access to your data vault</p>
        </div>
        <div className="flex space-x-3">
          <Button variant="secondary" onClick={() => setShowPrivacySettingsModal(true)} icon={<Settings className="w-4 h-4" />}>
            Privacy Settings
          </Button>
          <Button variant="primary" onClick={() => setShowAddAccessModal(true)} icon={<UserPlus className="w-4 h-4" />}>
            Grant Access
          </Button>
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

      {/* Loading State */}
      {isLoading && !accessList.length && (
        <div className="py-16 flex justify-center">
          <div className="animate-spin rounded-full h-10 w-10 border-4 border-blue-500 border-t-transparent"></div>
        </div>
      )}

      {/* Tabs */}
      <div className="mb-6">
        <div className="border-b border-gray-200 dark:border-gray-700">
          <nav className="-mb-px flex space-x-6">
            <button
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                statusFilter === 'all' || statusFilter === 'active' || statusFilter === 'expired' || statusFilter === 'revoked'
                  ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300 dark:hover:border-gray-600'
              }`}
              onClick={() => setStatusFilter('all')}
            >
              Active Access
              {accessList.filter(a => a.status === 'active').length > 0 && (
                <span className="ml-2 bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200 py-0.5 px-2 rounded-full text-xs">
                  {accessList.filter(a => a.status === 'active').length}
                </span>
              )}
            </button>
            <button
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                statusFilter === 'pending' || statusFilter === 'approved' || statusFilter === 'rejected'
                  ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300 dark:hover:border-gray-600'
              }`}
              onClick={() => setStatusFilter('pending')}
            >
              Access Requests
              {accessRequestList.filter(r => r.status === 'pending').length > 0 && (
                <span className="ml-2 bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200 py-0.5 px-2 rounded-full text-xs">
                  {accessRequestList.filter(r => r.status === 'pending').length}
                </span>
              )}
            </button>
            <button
              className="py-4 px-1 border-b-2 font-medium text-sm border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300 dark:hover:border-gray-600"
            >
              Access Logs
            </button>
          </nav>
        </div>
      </div>

      {/* Search and Filters */}
      <div className="mb-6 flex flex-col sm:flex-row space-y-3 sm:space-y-0 sm:items-center sm:justify-between">
        <div className="relative flex items-center">
          <Search className="absolute left-3 h-5 w-5 text-gray-400" />
          <input
            type="text"
            placeholder="Search by user or purpose..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pl-10 pr-3 py-2 w-full sm:w-64 border border-gray-300 dark:border-gray-700 rounded-md text-gray-900 dark:text-white bg-white dark:bg-gray-800 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
        </div>
        <div className="flex items-center space-x-3">
          <div className="relative">
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="appearance-none bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-md py-2 pl-3 pr-8 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="all">All Levels</option>
              <option value="read">Read</option>
              <option value="write">Write</option>
              <option value="compute">Compute</option>
              <option value="admin">Admin</option>
            </select>
            <ChevronDown className="absolute right-2 h-4 w-4 text-gray-700 dark:text-gray-300 pointer-events-none" />
          </div>
          <div className="relative">
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
              className="appearance-none bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-md py-2 pl-3 pr-8 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="newest">Newest First</option>
              <option value="oldest">Oldest First</option>
              <option value="user">By User</option>
              <option value="level">By Access Level</option>
              <option value="expiry">By Expiry Date</option>
            </select>
            <ChevronDown className="absolute right-2 h-4 w-4 text-gray-700 dark:text-gray-300 pointer-events-none" />
          </div>
        </div>
      </div>

      {/* Main Content */}
      {statusFilter === 'all' || statusFilter === 'active' || statusFilter === 'expired' || statusFilter === 'revoked' ? (
        // Active Access List
        <>
          {!isLoading && accessList.length === 0 ? (
            renderEmptyState()
          ) : (
            <div className="bg-white dark:bg-gray-800 shadow overflow-hidden sm:rounded-md">
              <ul className="divide-y divide-gray-200 dark:divide-gray-700">
                {filteredAccessList.map((access) => (
                  <li key={access.id}>
                    <div
                      className="px-4 py-4 flex items-center sm:px-6 hover:bg-gray-50 dark:hover:bg-gray-700 cursor-pointer transition duration-150 ease-in-out"
                      onClick={() => {
                        setSelectedAccess(access);
                        setShowAccessDetailModal(true);
                      }}
                    >
                      <div className="min-w-0 flex-1 sm:flex sm:items-center sm:justify-between">
                        <div>
                          <div className="flex items-center">
                            <div className="h-10 w-10 rounded-full bg-blue-100 dark:bg-blue-900 flex items-center justify-center">
                              <User className="h-6 w-6 text-blue-600 dark:text-blue-400" />
                            </div>
                            <div className="ml-4">
                              <p className="font-medium text-blue-600 dark:text-blue-400 truncate">{access.userName || shortenAddress(access.user)}</p>
                              <p className="text-sm text-gray-500 dark:text-gray-400 truncate">{access.user}</p>
                            </div>
                          </div>
                          {access.purpose && (
                            <div className="mt-2">
                              <p className="text-sm text-gray-600 dark:text-gray-300 truncate">
                                Purpose: {access.purpose.length > 60 ? access.purpose.substring(0, 60) + '...' : access.purpose}
                              </p>
                            </div>
                          )}
                        </div>
                        <div className="mt-4 flex-shrink-0 sm:mt-0">
                          <div className="flex flex-col sm:flex-row sm:space-x-3 space-y-2 sm:space-y-0 justify-end items-end sm:items-center">
                            <div className="flex space-x-2 items-center">
                              {getAccessLevelBadge(access.accessLevel)}
                              {getStatusBadge(access.status)}
                            </div>
                            <div className="text-sm text-gray-500 dark:text-gray-400">
                              {access.expiresAt ? `Expires: ${formatDate(access.expiresAt)}` : 'No expiration'}
                            </div>
                          </div>
                        </div>
                      </div>
                      <div className="ml-5 flex-shrink-0">
                        <ChevronDown className="h-5 w-5 text-gray-400" />
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </>
      ) : statusFilter === 'pending' || statusFilter === 'approved' || statusFilter === 'rejected' ? (
        // Access Requests
        <>
          {!isLoading && accessRequestList.length === 0 ? (
            <div className="text-center py-12">
              <div className="mx-auto h-12 w-12 text-gray-400">
                <UserPlus className="h-12 w-12" />
              </div>
              <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No access requests</h3>
              <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">There are currently no requests for access to this data vault.</p>
            </div>
          ) : (
            <div className="bg-white dark:bg-gray-800 shadow overflow-hidden sm:rounded-md">
              <ul className="divide-y divide-gray-200 dark:divide-gray-700">
                {filteredAccessRequests.map((request) => (
                  <li key={request.id}>
                    <div className="px-4 py-4 flex flex-col sm:flex-row sm:items-center sm:justify-between sm:px-6 hover:bg-gray-50 dark:hover:bg-gray-700">
                      <div className="flex items-center">
                        <div className="h-10 w-10 rounded-full bg-blue-100 dark:bg-blue-900 flex items-center justify-center">
                          <User className="h-6 w-6 text-blue-600 dark:text-blue-400" />
                        </div>
                        <div className="ml-4">
                          <p className="font-medium text-blue-600 dark:text-blue-400">{request.requestorName || shortenAddress(request.requestor)}</p>
                          <p className="text-sm text-gray-500 dark:text-gray-400 truncate">{request.requestor}</p>
                          <div className="mt-1 flex items-center">
                            {getAccessLevelBadge(request.accessLevel)}
                            <span className="ml-2 text-sm text-gray-500 dark:text-gray-400">
                              Requested: {formatDate(request.createdAt)}
                            </span>
                          </div>
                        </div>
                      </div>
                      <div className="mt-4 sm:mt-0">
                        {request.status === 'pending' ? (
                          <div className="flex space-x-2">
                            <Button variant="danger" size="small" onClick={() => handleRejectRequest(request.id)}>
                              Reject
                            </Button>
                            <Button variant="success" size="small" onClick={() => handleApproveRequest(request.id)}>
                              Approve
                            </Button>
                          </div>
                        ) : (
                          <div className="flex items-center">
                            {getStatusBadge(request.status)}
                            <span className="ml-2 text-sm text-gray-500 dark:text-gray-400">{formatDate(request.updatedAt)}</span>
                          </div>
                        )}
                      </div>
                    </div>
                    <div className="px-4 py-3 bg-gray-50 dark:bg-gray-700 sm:px-6">
                      <p className="text-sm text-gray-700 dark:text-gray-300">
                        <span className="font-medium">Purpose:</span> {request.purpose}
                      </p>
                      {request.additionalDetails && (
                        <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">{request.additionalDetails}</p>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </>
      ) : (
        // Access History/Logs
        <div className="bg-white dark:bg-gray-800 shadow overflow-hidden sm:rounded-md">
          <div className="px-4 py-8 text-center text-gray-500 dark:text-gray-400">
            <p>Access history view is not implemented in this version.</p>
          </div>
        </div>
      )}

      {/* Modals */}
      {/* Access Detail Modal */}
      <Modal
        isOpen={showAccessDetailModal}
        onClose={() => {
          setShowAccessDetailModal(false);
          setSelectedAccess(null);
        }}
        title="Access Details"
        size="large"
        footer={
          <div className="flex justify-between">
            <Button
              variant="danger"
              onClick={() => {
                setShowAccessDetailModal(false);
                setShowRevokeConfirmModal(true);
              }}
              icon={<UserMinus className="w-4 h-4" />}
            >
              Revoke Access
            </Button>
            <Button variant="secondary" onClick={() => setShowAccessDetailModal(false)}>
              Close
            </Button>
          </div>
        }
      >
        {selectedAccess && (
          <div className="space-y-6">
            <div className="bg-gray-50 dark:bg-gray-800 p-4 rounded-lg">
              <div className="flex items-center">
                <div className="h-12 w-12 rounded-full bg-blue-100 dark:bg-blue-900 flex items-center justify-center">
                  <User className="h-7 w-7 text-blue-600 dark:text-blue-400" />
                </div>
                <div className="ml-4">
                  <h3 className="text-lg font-medium text-gray-900 dark:text-white">{selectedAccess.userName || shortenAddress(selectedAccess.user, 8)}</h3>
                  <p className="text-sm text-gray-500 dark:text-gray-400">{selectedAccess.user}</p>
                </div>
              </div>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="col-span-1">
                <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-2">Access Details</h4>
                <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                  <div className="space-y-3">
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Status:</span>
                      <span className="text-sm text-gray-900 dark:text-white">{getStatusBadge(selectedAccess.status)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Access Level:</span>
                      <span className="text-sm text-gray-900 dark:text-white">{getAccessLevelBadge(selectedAccess.accessLevel)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Granted:</span>
                      <span className="text-sm text-gray-900 dark:text-white">{formatDateTime(selectedAccess.grantedAt)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Expires:</span>
                      <span className="text-sm text-gray-900 dark:text-white">{selectedAccess.expiresAt ? formatDateTime(selectedAccess.expiresAt) : 'Never'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Last Access:</span>
                      <span className="text-sm text-gray-900 dark:text-white">{selectedAccess.lastAccessedAt ? formatDateTime(selectedAccess.lastAccessedAt) : 'Never'}</span>
                    </div>
                  </div>
                </div>
              </div>
              <div className="col-span-1">
                <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-2">Access Controls</h4>
                <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Allow Re-export:</span>
                      <span className="text-sm text-gray-900 dark:text-white">
                        {selectedAccess.allowReExport ? <CheckCircle className="w-5 h-5 text-green-500" /> : <XCircle className="w-5 h-5 text-red-500" />}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Allow Derived Data:</span>
                      <span className="text-sm text-gray-900 dark:text-white">
                        {selectedAccess.allowDerivedData ? <CheckCircle className="w-5 h-5 text-green-500" /> : <XCircle className="w-5 h-5 text-red-500" />}
                      </span>
                    </div>
                    <div className="pt-2 pb-1 border-t border-gray-200 dark:border-gray-700">
                      <p className="text-sm font-medium text-gray-900 dark:text-white">Privacy Constraints:</p>
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                      {selectedAccess.privacyConstraints && Object.entries(selectedAccess.privacyConstraints)
                        .filter(([key]) => key !== 'privacyBudget')
                        .map(([key, value]) => (
                          <div key={key} className={`flex items-center p-2 rounded-md ${value ? 'bg-blue-50 dark:bg-blue-900/20' : 'bg-gray-50 dark:bg-gray-900/20'}`}>
                            <div className={`flex-shrink-0 ${value ? 'text-blue-500' : 'text-gray-400'}`}>
                              {getPrivacyIcon(key)}
                            </div>
                            <span className={`ml-2 text-xs font-medium ${value ? 'text-blue-700 dark:text-blue-300' : 'text-gray-500 dark:text-gray-400'}`}>
                              {key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase())}
                            </span>
                          </div>
                        ))}
                    </div>
                    {selectedAccess.privacyConstraints?.privacyBudget && selectedAccess.privacyConstraints?.differentialPrivacy && (
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-gray-500 dark:text-gray-400">Privacy Budget (ε):</span>
                        <span className="text-sm text-gray-900 dark:text-white">{selectedAccess.privacyConstraints.privacyBudget.toFixed(1)}</span>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
            <div>
              <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-2">Access Purpose</h4>
              <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                <p className="text-sm text-gray-700 dark:text-gray-300">{selectedAccess.purpose || 'No purpose specified'}</p>
              </div>
            </div>
            <div>
              <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-2">Access Logs</h4>
              <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 max-h-60 overflow-y-auto">
                {selectedAccess.accessLogs && selectedAccess.accessLogs.length > 0 ? (
                  <ul className="space-y-2">
                    {selectedAccess.accessLogs.map((log, index) => (
                      <li key={index} className="text-sm">
                        <span className="text-gray-500 dark:text-gray-400">{formatDateTime(log.timestamp)}:</span>
                        <span className="ml-2 text-gray-900 dark:text-white">{log.action}</span>
                        {log.details && <span className="ml-2 text-gray-500 dark:text-gray-400">({log.details})</span>}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-sm text-gray-500 dark:text-gray-400">No access logs available</p>
                )}
              </div>
            </div>
          </div>
        )}
      </Modal>

      {/* Add Access Modal */}
      <Modal
        isOpen={showAddAccessModal}
        onClose={() => setShowAddAccessModal(false)}
        title="Grant Access"
        size="large"
        variant="primary"
      >
        <div className="space-y-6">
          <div className="bg-blue-50 dark:bg-blue-900/20 p-4 rounded-lg">
            <div className="flex">
              <Shield className="h-6 w-6 text-blue-500" />
              <div className="ml-3">
                <h3 className="text-sm font-medium text-blue-800 dark:text-blue-200">Privacy-Preserving Access</h3>
                <p className="mt-1 text-sm text-blue-700 dark:text-blue-300">
                  Access to this data vault will be protected by zero-knowledge proofs and encrypted connections.
                </p>
              </div>
            </div>
          </div>
          <div className="space-y-4">
            <div>
              <label htmlFor="userAddress" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                User Address <span className="text-red-500">*</span>
              </label>
              <input
                type="text"
                id="userAddress"
                value={newAccessForm.userAddress}
                onChange={(e) => setNewAccessForm({ ...newAccessForm, userAddress: e.target.value })}
                className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-700 dark:bg-gray-800 dark:text-white shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                placeholder="0x..."
                required
              />
              <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">Enter the wallet address of the user you want to grant access to</p>
            </div>
            <div>
              <label htmlFor="accessLevel" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                Access Level <span className="text-red-500">*</span>
              </label>
              <select
                id="accessLevel"
                value={newAccessForm.accessLevel}
                onChange={(e) => setNewAccessForm({ ...newAccessForm, accessLevel: e.target.value })}
                className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-700 dark:bg-gray-800 dark:text-white shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
              >
                <option value="read">Read (View data only)</option>
                <option value="compute">Compute (Run privacy-preserving computations)</option>
                <option value="write">Write (Modify data)</option>
                <option value="admin">Admin (Full access)</option>
              </select>
              <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">Determines what actions the user can perform on the data</p>
            </div>
            <div>
              <label htmlFor="expiresAt" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                Access Expiration
              </label>
              <input
                type="date"
                id="expiresAt"
                value={newAccessForm.expiresAt}
                onChange={(e) => setNewAccessForm({ ...newAccessForm, expiresAt: e.target.value })}
                className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-700 dark:bg-gray-800 dark:text-white shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
              />
              <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">Leave blank for permanent access (not recommended)</p>
            </div>
            <div>
              <label htmlFor="purpose" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                Access Purpose <span className="text-red-500">*</span>
              </label>
              <textarea
                id="purpose"
                value={newAccessForm.purpose}
                onChange={(e) => setNewAccessForm({ ...newAccessForm, purpose: e.target.value })}
                rows={3}
                className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-700 dark:bg-gray-800 dark:text-white shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                placeholder="Why does this user need access to the data?"
                required
              />
              <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">Describe why you are granting access and how the data will be used</p>
            </div>
          </div>
          <div>
            <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-2">Additional Permissions</h4>
            <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
              <div className="space-y-4">
                <div className="flex items-start">
                  <input
                    id="allowReExport"
                    type="checkbox"
                    checked={newAccessForm.allowReExport}
                    onChange={(e) => setNewAccessForm({ ...newAccessForm, allowReExport: e.target.checked })}
                    className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded dark:border-gray-700 dark:bg-gray-800"
                  />
                  <label htmlFor="allowReExport" className="ml-3 block text-sm font-medium text-gray-700 dark:text-gray-300">
                    Allow Re-export
                  </label>
                  <p className="ml-3 text-xs text-gray-500 dark:text-gray-400">Allow the user to export the data outside the platform (requires ZKP verification)</p>
                </div>
                <div className="flex items-start">
                  <input
                    id="allowDerivedData"
                    type="checkbox"
                    checked={newAccessForm.allowDerivedData}
                    onChange=(e) => setNewAccessForm({ ...newAccessForm, allowDerivedData: e.target.checked })}
                    className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded dark:border-gray-700 dark:bg-gray-800"
                  />
                  <label htmlFor="allowDerivedData" className="ml-3 block text-sm font-medium text-gray-700 dark:text-gray-300">
                    Allow Derived Data
                  </label>
                  <p className="ml-3 text-xs text-gray-500 dark:text-gray-400">Allow the user to create and own new datasets derived from this data</p>
                </div>
              </div>
            </div>
          </div>
          <div>
            <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-2">Privacy Constraints</h4>
            <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
              <div className="space-y-4">
                <div className="flex items-start">
                  <input
                    id="differentialPrivacy"
                    type="checkbox"
                    checked={newAccessForm.privacyConstraints.differentialPrivacy}
                    onChange={(e) => setNewAccessForm({
                      ...newAccessForm,
                      privacyConstraints: { ...newAccessForm.privacyConstraints, differentialPrivacy: e.target.checked }
                    })}
                    className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded dark:border-gray-700 dark:bg-gray-800"
                  />
                  <label htmlFor="differentialPrivacy" className="ml-3 block text-sm font-medium text-gray-700 dark:text-gray-300">
                    Differential Privacy
                  </label>
                  <p className="ml-3 text-xs text-gray-500 dark:text-gray-400">Add mathematical noise to protect individual data points</p>
                </div>
                <div className="flex items-start">
                  <input
                    id="secureMpc"
                    type="checkbox"
                    checked={newAccessForm.privacyConstraints.secureMpc}
                    onChange={(e) => setNewAccessForm({
                      ...newAccessForm,
                      privacyConstraints: { ...newAccessForm.privacyConstraints, secureMpc: e.target.checked }
                    })}
                    className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded dark:border-gray-700 dark:bg-gray-800"
                  />
                  <label htmlFor="secureMpc" className="ml-3 block text-sm font-medium text-gray-700 dark:text-gray-300">
                    Secure Multi-Party Computation
                  </label>
                  <p className="ml-3 text-xs text-gray-500 dark:text-gray-400">Enable encrypted computations without exposing inputs</p>
                </div>
                <div className="flex items-start">
                  <input
                    id="zkp"
                    type="checkbox"
                    checked={newAccessForm.privacyConstraints.zkp}
                    onChange={(e) => setNewAccessForm({
                      ...newAccessForm,
                      privacyConstraints: { ...newAccessForm.privacyConstraints, zkp: e.target.checked }
                    })}
                    className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded dark:border-gray-700 dark:bg-gray-800"
                  />
                  <label htmlFor="zkp" className="ml-3 block text-sm font-medium text-gray-700 dark:text-gray-300">
                    Zero-Knowledge Proofs
                  </label>
                  <p className="ml-3 text-xs text-gray-500 dark:text-gray-400">Verify data properties without revealing the data</p>
                </div>
                <div className="flex items-start">
                  <input
                    id="federatedLearning"
                    type="checkbox"
                    checked={newAccessForm.privacyConstraints.federatedLearning}
                    onChange={(e) => setNewAccessForm({
                      ...newAccessForm,
                      privacyConstraints: { ...newAccessForm.privacyConstraints, federatedLearning: e.target.checked }
                    })}
                    className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded dark:border-gray-700 dark:bg-gray-800"
                  />
                  <label htmlFor="federatedLearning" className="ml-3 block text-sm font-medium text-gray-700 dark:text-gray-300">
                    Federated Learning
                  </label>
                  <p className="ml-3 text-xs text-gray-500 dark:text-gray-400">Train models across decentralized datasets</p>
                </div>
              </div>
            </div>
          </div>
          <div className="flex justify-end space-x-3 pt-4 border-t border-gray-200 dark:border-gray-700">
            <Button variant="secondary" onClick={() => setShowAddAccessModal(false)}>
              Cancel
            </Button>
            <Button
              variant="primary"
              onClick={handleAddAccess}
              isLoading={isLoading}
              isDisabled={!newAccessForm.userAddress || !newAccessForm.purpose}
            >
              Grant Access
            </Button>
          </div>
        </div>
      </Modal>

      {/* Revoke Confirmation Modal */}
      <Modal
        isOpen={showRevokeConfirmModal}
        onClose={() => setShowRevokeConfirmModal(false)}
        title="Revoke Access"
        variant="danger"
      >
        <div className="space-y-4">
          <div className="bg-red-50 dark:bg-red-900/20 p-4 rounded-lg">
            <div className="flex">
              <AlertTriangle className="h-6 w-6 text-red-600 dark:text-red-400" />
              <div className="ml-3">
                <h3 className="text-sm font-medium text-red-800 dark:text-red-200">Confirm Access Revocation</h3>
                <p className="mt-1 text-sm text-red-700 dark:text-red-300">
                  Revoking access is immediate and cannot be undone. The user will lose all access to this data vault.
                </p>
              </div>
            </div>
          </div>
          {selectedAccess && (
            <div>
              <p className="text-sm text-gray-700 dark:text-gray-300">
                Are you sure you want to revoke access for{' '}
                <span className="font-medium">{selectedAccess.userName || shortenAddress(selectedAccess.user, 8)}</span>?
              </p>
              <div className="mt-3 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-3">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-gray-500 dark:text-gray-400">Access Level:</span>
                  <span>{getAccessLevelBadge(selectedAccess.accessLevel)}</span>
                </div>
                <div className="flex items-center justify-between text-sm mt-2">
                  <span className="text-gray-500 dark:text-gray-400">Granted:</span>
                  <span className="text-gray-900 dark:text-white">{formatDate(selectedAccess.grantedAt)}</span>
                </div>
                <div className="flex items-center justify-between text-sm mt-2">
                  <span className="text-gray-500 dark:text-gray-400">Purpose:</span>
                  <span className="text-gray-900 dark:text-white max-w-xs truncate">{selectedAccess.purpose || 'N/A'}</span>
                </div>
              </div>
            </div>
          )}
          <div className="flex justify-end space-x-3 pt-4">
            <Button variant="secondary" onClick={() => setShowRevokeConfirmModal(false)}>
              Cancel
            </Button>
            <Button variant="danger" onClick={handleRevokeAccess} isLoading={isLoading}>
              Revoke Access
            </Button>
          </div>
        </div>
      </Modal>

      {/* Privacy Settings Modal */}
      <Modal
        isOpen={showPrivacySettingsModal}
        onClose={() => setShowPrivacySettingsModal(false)}
        title="Privacy Settings"
        size="large"
        variant="primary"
      >
        <div className="space-y-6">
          <div className="bg-blue-50 dark:bg-blue-900/20 p-4 rounded-lg">
            <div className="flex">
              <Shield className="h-6 w-6 text-blue-500" />
              <div className="ml-3">
                <h3 className="text-sm font-medium text-blue-800 dark:text-blue-200">Privacy Configuration</h3>
                <p className="mt-1 text-sm text-blue-700 dark:text-blue-300">
                  Configure default privacy settings for new access grants.
                </p>
              </div>
            </div>
          </div>
          {vaultInfo && (
            <div className="space-y-4">
              <div>
                <label htmlFor="defaultAccessLevel" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                  Default Access Level
                </label>
                <select
                  id="defaultAccessLevel"
                  value={vaultInfo.defaultAccessLevel || 'read'}
                  onChange={(e) => handleUpdateVaultSettings({ defaultAccessLevel: e.target.value })}
                  className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-700 dark:bg-gray-800 dark:text-white shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                >
                  <option value="read">Read</option>
                  <option value="compute">Compute</option>
                  <option value="write">Write</option>
                  <option value="admin">Admin</option>
                </select>
              </div>
              <div>
                <label htmlFor="defaultExpirationDays" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                  Default Access Duration (Days)
                </label>
                <input
                  type="number"
                  id="defaultExpirationDays"
                  value={vaultInfo.defaultExpirationDays || 30}
                  onChange={(e) => handleUpdateVaultSettings({ defaultExpirationDays: parseInt(e.target.value) })}
                  min="1"
                  max="365"
                  className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-700 dark:bg-gray-800 dark:text-white shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                />
              </div>
              {/* Add more privacy settings as needed */}
            </div>
          )}
          <div className="flex justify-end space-x-3 pt-4 border-t border-gray-200 dark:border-gray-700">
            <Button variant="secondary" onClick={() => setShowPrivacySettingsModal(false)}>
              Close
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
};

AccessControl.propTypes = {
  vaultId: PropTypes.string.isRequired,
  onUpdated: PropTypes.func,
  className: PropTypes.string,
};

export default AccessControl;
