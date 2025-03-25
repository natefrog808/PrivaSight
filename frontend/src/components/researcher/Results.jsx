/**
 * Results Component
 * 
 * A comprehensive UI for displaying the results of dataset queries or computations
 * on the PrivaSight platform, with privacy-preserving controls and detailed metadata.
 */

import React, { useState, useEffect } from 'react';
import PropTypes from 'prop-types';
import { useDataVault } from '../../hooks/useDataVault';
import { usePrivacyLayer } from '../../hooks/usePrivacyLayer';

// Icons (assumed to be available in the project)
import {
  Shield,
  Info,
  Download,
  AlertTriangle,
  CheckCircle,
  X,
  Database,
} from '../icons';

// Components (assumed to be available in the project)
import Button from '../common/Button';

const Results = ({
  queryId,
  onError,
  className = '',
  ...props
}) => {
  // ### State Management
  const [results, setResults] = useState(null); // Holds the fetched results
  const [isLoading, setIsLoading] = useState(true); // Tracks loading state
  const [error, setError] = useState(null); // Stores error messages
  const [isVerifying, setIsVerifying] = useState(false); // Tracks proof verification state
  const [verificationResult, setVerificationResult] = useState(null); // Stores proof verification outcome

  // ### Custom Hooks
  const { getQueryResults } = useDataVault(); // Fetches query results
  const { verifyProof } = usePrivacyLayer(); // Verifies privacy proofs

  // ### Effects
  // Fetch results when queryId changes
  useEffect(() => {
    const fetchResults = async () => {
      if (!queryId) return;
      try {
        setIsLoading(true);
        const data = await getQueryResults(queryId);
        setResults(data);
        setError(null);
      } catch (err) {
        console.error('Failed to fetch query results:', err);
        setError('Failed to fetch query results. Please try again later.');
        if (onError) onError(err);
      } finally {
        setIsLoading(false);
      }
    };
    fetchResults();
  }, [queryId, getQueryResults, onError]);

  // ### Event Handlers
  const handleVerifyProof = async () => {
    if (!results?.privacyMetadata?.proof) return;
    setIsVerifying(true);
    try {
      const isValid = await verifyProof(results.privacyMetadata.proof);
      setVerificationResult(isValid ? 'Valid' : 'Invalid');
    } catch (err) {
      console.error('Verification failed:', err);
      setVerificationResult('Error');
    } finally {
      setIsVerifying(false);
    }
  };

  // ### Render Helpers
  // **Privacy Metadata Section**
  const renderPrivacyMetadata = () => {
    if (!results?.privacyMetadata) return null;
    const { technology, epsilon, proof } = results.privacyMetadata;
    return (
      <div className="mb-6 p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
        <div className="flex items-center justify-between">
          <div className="flex items-center">
            <Shield className="h-5 w-5 text-blue-500 mr-2" />
            <span className="text-sm font-medium text-blue-800 dark:text-blue-200">
              Privacy Technology: {technology}
            </span>
            {epsilon && (
              <span className="ml-2 text-sm text-blue-700 dark:text-blue-300">
                (ε = {epsilon})
              </span>
            )}
          </div>
          {proof && (
            <Button
              variant="secondary"
              size="small"
              onClick={handleVerifyProof}
              isLoading={isVerifying}
            >
              {verificationResult ? (
                verificationResult === 'Valid' ? (
                  <CheckCircle className="h-4 w-4 text-green-500 mr-1" />
                ) : (
                  <X className="h-4 w-4 text-red-500 mr-1" />
                )
              ) : (
                'Verify Proof'
              )}
              {verificationResult || 'Verify'}
            </Button>
          )}
        </div>
      </div>
    );
  };

  // **Query Details Section**
  const renderQueryDetails = () => {
    if (!results?.queryDetails) return null;
    const { queryString, executionTime } = results.queryDetails;
    return (
      <div className="mb-6 p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
        <h3 className="text-sm font-medium text-gray-900 dark:text-white">Query Details</h3>
        <dl className="mt-2 grid grid-cols-1 gap-x-4 gap-y-2 sm:grid-cols-2">
          {queryString && (
            <div>
              <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Query</dt>
              <dd className="mt-1 text-sm text-gray-900 dark:text-white break-words">{queryString}</dd>
            </div>
          )}
          {executionTime && (
            <div>
              <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Execution Time</dt>
              <dd className="mt-1 text-sm text-gray-900 dark:text-white">
                {new Date(executionTime).toLocaleString()}
              </dd>
            </div>
          )}
        </dl>
      </div>
    );
  };

  // **Tabular Results**
  const renderTableResults = () => {
    if (!results?.data || results.data.length === 0) return null;
    const columns = Object.keys(results.data[0]);
    return (
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead className="bg-gray-50 dark:bg-gray-800">
            <tr>
              {columns.map((col) => (
                <th
                  key={col}
                  className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider"
                >
                  {col}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-700">
            {results.data.map((row, rowIndex) => (
              <tr key={rowIndex}>
                {columns.map((col) => (
                  <td
                    key={col}
                    className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white"
                  >
                    {row[col]}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  };

  // **Aggregate Results**
  const renderAggregateResults = () => {
    if (!results?.data) return null;
    return (
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {Object.entries(results.data).map(([key, value]) => (
          <div
            key={key}
            className="p-4 bg-white dark:bg-gray-800 rounded-lg shadow"
          >
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 capitalize">{key}</dt>
            <dd className="mt-1 text-lg font-semibold text-gray-900 dark:text-white">{value}</dd>
          </div>
        ))}
      </div>
    );
  };

  // **Determine Result Type and Render**
  const renderResults = () => {
    if (!results) return null;
    switch (results.type) {
      case 'table':
        return renderTableResults();
      case 'aggregate':
        return renderAggregateResults();
      default:
        return (
          <div className="text-center py-16">
            <Database className="mx-auto h-12 w-12 text-gray-400" />
            <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">Unsupported Result Type</h3>
            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
              This result type is not supported by the current viewer.
            </p>
          </div>
        );
    }
  };

  // ### Main Render Logic
  if (isLoading) {
    return (
      <div className="py-16 flex justify-center">
        <div className="animate-spin rounded-full h-10 w-10 border-4 border-blue-500 border-t-transparent"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="mb-6 bg-red-50 dark:bg-red-900/20 p-4 rounded-lg">
        <div className="flex">
          <AlertTriangle className="h-5 w-5 text-red-500" />
          <div className="ml-3">
            <p className="text-sm text-red-700 dark:text-red-300">{error}</p>
          </div>
        </div>
      </div>
    );
  }

  if (!results || !results.data) {
    return (
      <div className="text-center py-16">
        <Database className="mx-auto h-12 w-12 text-gray-400" />
        <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No Results Found</h3>
        <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
          The query returned no data.
        </p>
      </div>
    );
  }

  return (
    <div className={`results-container ${className}`} {...props}>
      {renderQueryDetails()}
      {renderPrivacyMetadata()}
      {renderResults()}
      <div className="mt-6 flex justify-end space-x-3">
        <Button
          variant="secondary"
          icon={<Download className="w-4 h-4" />}
        >
          Download Results
        </Button>
        <Button
          variant="primary"
          icon={<Info className="w-4 h-4" />}
        >
          View Privacy Details
        </Button>
      </div>
    </div>
  );
};

// ### Prop Types
Results.propTypes = {
  queryId: PropTypes.string.isRequired, // Unique identifier for the query
  onError: PropTypes.func, // Callback for error handling
  className: PropTypes.string, // Custom CSS classes
};

export default Results;
