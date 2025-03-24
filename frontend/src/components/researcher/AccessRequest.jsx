/**
 * AccessRequest Component
 * 
 * A comprehensive UI for requesting access to datasets on the PrivaSight platform
 * with privacy-preserving controls and detailed purpose specification.
 */

import React, { useState, useEffect } from 'react';
import PropTypes from 'prop-types';
import { useDataVault } from '../../hooks/useDataVault';
import { usePrivacyLayer } from '../../hooks/usePrivacyLayer';

// Icons
import {
  Shield,
  Lock,
  Users,
  Clock,
  Calendar,
  CheckCircle,
  AlertTriangle,
  Info,
  Database,
  Shuffle,
  ZeroKnowledge,
} from '../icons';

// Components
import Button from '../common/Button';
import Modal from '../common/Modal';

const AccessRequest = ({
  datasetId,
  onRequestSubmitted,
  onCancel,
  className = '',
  ...props
}) => {
  // **State Management**
  const [dataset, setDataset] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [formErrors, setFormErrors] = useState({});
  const [currentStep, setCurrentStep] = useState(0);
  const [showConfirmModal, setShowConfirmModal] = useState(false);
  const [requestStatus, setRequestStatus] = useState(null);

  // Form data state
  const [requestData, setRequestData] = useState({
    accessLevel: 'read',
    purpose: '',
    dataUsageDescription: '',
    requestedDuration: 30,
    organization: '',
    projectName: '',
    privacyRequirements: {
      differentialPrivacy: true,
      secureMpc: false,
      zkp: true,
      federatedLearning: false,
      privacyBudget: 1.0,
    },
    termsAgreed: false,
    privacyConsent: false,
    userFields: [],
    allowedOperations: [],
  });

  // **Custom Hooks**
  const { getDatasetDetails, requestDatasetAccess } = useDataVault();
  const { generatePrivacyProof } = usePrivacyLayer();

  // **Effects**
  useEffect(() => {
    const loadDataset = async () => {
      if (!datasetId) return;
      try {
        setIsLoading(true);
        const datasetDetails = await getDatasetDetails(datasetId);
        setDataset(datasetDetails);
        if (datasetDetails.allowedOperations) {
          setRequestData((prev) => ({
            ...prev,
            allowedOperations: datasetDetails.allowedOperations
              .filter((op) => op.defaultSelected)
              .map((op) => op.id),
          }));
        }
        if (datasetDetails.requiredUserFields) {
          setRequestData((prev) => ({
            ...prev,
            userFields: datasetDetails.requiredUserFields.map((field) => ({
              id: field.id,
              name: field.name,
              value: '',
            })),
          }));
        }
        setError(null);
      } catch (err) {
        console.error('Failed to load dataset details:', err);
        setError('Failed to load dataset details. Please try again later.');
      } finally {
        setIsLoading(false);
      }
    };
    loadDataset();
  }, [datasetId, getDatasetDetails]);

  // **Form Handlers**
  const handleInputChange = (field, value) => {
    setRequestData((prev) => ({ ...prev, [field]: value }));
    if (formErrors[field]) setFormErrors((prev) => ({ ...prev, [field]: null }));
  };

  const handlePrivacyRequirementChange = (requirement, value) => {
    setRequestData((prev) => ({
      ...prev,
      privacyRequirements: { ...prev.privacyRequirements, [requirement]: value },
    }));
  };

  const handleUserFieldChange = (fieldId, value) => {
    setRequestData((prev) => ({
      ...prev,
      userFields: prev.userFields.map((field) =>
        field.id === fieldId ? { ...field, value } : field
      ),
    }));
    if (formErrors[`userField_${fieldId}`]) {
      setFormErrors((prev) => ({ ...prev, [`userField_${fieldId}`]: null }));
    }
  };

  const toggleAllowedOperation = (operationId) => {
    setRequestData((prev) => {
      const operations = prev.allowedOperations.includes(operationId)
        ? prev.allowedOperations.filter((id) => id !== operationId)
        : [...prev.allowedOperations, operationId];
      return { ...prev, allowedOperations: operations };
    });
  };

  // **Validation**
  const validateStep = (step) => {
    const errors = {};
    if (step === 0) {
      if (!requestData.purpose.trim()) errors.purpose = 'Purpose is required';
      else if (requestData.purpose.length < 20) errors.purpose = 'Please provide a more detailed purpose';
      if (!requestData.projectName.trim()) errors.projectName = 'Project name is required';
      if (!requestData.organization.trim()) errors.organization = 'Organization is required';
    } else if (step === 1) {
      if (
        requestData.privacyRequirements.differentialPrivacy &&
        (requestData.privacyRequirements.privacyBudget < 0.1 || requestData.privacyRequirements.privacyBudget > 10)
      ) {
        errors.privacyBudget = 'Privacy budget must be between 0.1 and 10';
      }
      if (!Object.values(requestData.privacyRequirements).some((val) => val === true)) {
        errors.privacyTechnology = 'At least one privacy technology must be selected';
      }
    } else if (step === 2) {
      requestData.userFields.forEach((field) => {
        if (field.required && !field.value.trim()) errors[`userField_${field.id}`] = `${field.name} is required`;
      });
      if (dataset?.allowedOperations?.length > 0 && requestData.allowedOperations.length === 0) {
        errors.allowedOperations = 'At least one operation must be selected';
      }
    } else if (step === 3) {
      if (!requestData.termsAgreed) errors.termsAgreed = 'You must agree to the terms and conditions';
      if (!requestData.privacyConsent) errors.privacyConsent = 'You must consent to the privacy policy';
    }
    setFormErrors(errors);
    return Object.keys(errors).length === 0;
  };

  // **Event Handlers**
  const handleNextStep = () => {
    if (validateStep(currentStep)) {
      if (currentStep < 3) setCurrentStep(currentStep + 1);
      else setShowConfirmModal(true);
    }
  };

  const handlePreviousStep = () => {
    if (currentStep > 0) setCurrentStep(currentStep - 1);
    else if (onCancel) onCancel();
  };

  const handleSubmitRequest = async () => {
    try {
      setIsLoading(true);
      let privacyProof = null;
      if (requestData.privacyRequirements.zkp) privacyProof = await generatePrivacyProof(datasetId);
      const requestResult = await requestDatasetAccess(
        datasetId,
        requestData.accessLevel,
        requestData.purpose,
        {
          dataUsageDescription: requestData.dataUsageDescription,
          requestedDuration: requestData.requestedDuration,
          organization: requestData.organization,
          projectName: requestData.projectName,
          privacyRequirements: requestData.privacyRequirements,
          userFields: requestData.userFields,
          allowedOperations: requestData.allowedOperations,
          privacyProof,
        }
      );
      setRequestStatus('success');
      setShowConfirmModal(false);
      if (onRequestSubmitted) onRequestSubmitted(requestResult);
    } catch (err) {
      console.error('Failed to submit access request:', err);
      setError('Failed to submit access request. Please try again later.');
      setRequestStatus('error');
    } finally {
      setIsLoading(false);
    }
  };

  // **Helper Functions**
  const getPrivacyTechnologyIcon = (technology) => {
    switch (technology) {
      case 'differentialPrivacy': return <Shield className="w-5 h-5" />;
      case 'federatedLearning': return <Shuffle className="w-5 h-5" />;
      case 'secureMpc': return <Users className="w-5 h-5" />;
      case 'zkp': return <ZeroKnowledge className="w-5 h-5" />;
      default: return <Lock className="w-5 h-5" />;
    }
  };

  // **Render Helpers**
  const renderStep = () => {
    switch (currentStep) {
      case 0: return renderPurposeStep();
      case 1: return renderPrivacyRequirementsStep();
      case 2: return renderDataAccessPlanStep();
      case 3: return renderReviewStep();
      default: return null;
    }
  };

  const renderPurposeStep = () => (
    <div className="space-y-6">
      <div className="bg-blue-50 dark:bg-blue-900/20 p-4 rounded-lg">
        <div className="flex">
          <Info className="h-6 w-6 text-blue-500" />
          <div className="ml-3">
            <h3 className="text-sm font-medium text-blue-800 dark:text-blue-200">Access Request</h3>
            <p className="mt-1 text-sm text-blue-700 dark:text-blue-300">
              Provide details about why you need access and how you plan to use it.
            </p>
          </div>
        </div>
      </div>
      <div>
        <label htmlFor="organization" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
          Organization <span className="text-red-500">*</span>
        </label>
        <input
          type="text"
          id="organization"
          className={`mt-1 block w-full rounded-md shadow-sm sm:text-sm ${
            formErrors.organization ? 'border-red-300' : 'border-gray-300 dark:border-gray-700'
          } dark:bg-gray-800 dark:text-white`}
          value={requestData.organization}
          onChange={(e) => handleInputChange('organization', e.target.value)}
          placeholder="Your company or institution"
        />
        {formErrors.organization && (
          <p className="mt-1 text-sm text-red-600 dark:text-red-400">{formErrors.organization}</p>
        )}
      </div>
      <div>
        <label htmlFor="projectName" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
          Project Name <span className="text-red-500">*</span>
        </label>
        <input
          type="text"
          id="projectName"
          className={`mt-1 block w-full rounded-md shadow-sm sm:text-sm ${
            formErrors.projectName ? 'border-red-300' : 'border-gray-300 dark:border-gray-700'
          } dark:bg-gray-800 dark:text-white`}
          value={requestData.projectName}
          onChange={(e) => handleInputChange('projectName', e.target.value)}
          placeholder="Name of your research or project"
        />
        {formErrors.projectName && (
          <p className="mt-1 text-sm text-red-600 dark:text-red-400">{formErrors.projectName}</p>
        )}
      </div>
      <div>
        <label htmlFor="purpose" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
          Access Purpose <span className="text-red-500">*</span>
        </label>
        <textarea
          id="purpose"
          rows={4}
          className={`mt-1 block w-full rounded-md shadow-sm sm:text-sm ${
            formErrors.purpose ? 'border-red-300' : 'border-gray-300 dark:border-gray-700'
          } dark:bg-gray-800 dark:text-white`}
          value={requestData.purpose}
          onChange={(e) => handleInputChange('purpose', e.target.value)}
          placeholder="Describe why you need access and your specific goals."
        />
        {formErrors.purpose && (
          <p className="mt-1 text-sm text-red-600 dark:text-red-400">{formErrors.purpose}</p>
        )}
      </div>
      <div>
        <label htmlFor="accessLevel" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
          Access Level <span className="text-red-500">*</span>
        </label>
        <select
          id="accessLevel"
          className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-700 shadow-sm sm:text-sm dark:bg-gray-800 dark:text-white"
          value={requestData.accessLevel}
          onChange={(e) => handleInputChange('accessLevel', e.target.value)}
        >
          <option value="read">Read (View data only)</option>
          <option value="compute">Compute (Run privacy-preserving computations)</option>
          {dataset?.allowsWriteAccess && <option value="write">Write (Modify data)</option>}
        </select>
      </div>
      <div>
        <label htmlFor="requestedDuration" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
          Requested Duration (Days)
        </label>
        <input
          type="number"
          id="requestedDuration"
          className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-700 shadow-sm sm:text-sm dark:bg-gray-800 dark:text-white"
          value={requestData.requestedDuration}
          onChange={(e) => handleInputChange('requestedDuration', parseInt(e.target.value))}
          min="1"
          max="365"
        />
      </div>
    </div>
  );

  const renderPrivacyRequirementsStep = () => (
    <div className="space-y-6">
      <div className="bg-blue-50 dark:bg-blue-900/20 p-4 rounded-lg">
        <div className="flex">
          <Shield className="h-6 w-6 text-blue-500" />
          <div className="ml-3">
            <h3 className="text-sm font-medium text-blue-800 dark:text-blue-200">Privacy Requirements</h3>
            <p className="mt-1 text-sm text-blue-700 dark:text-blue-300">Configure privacy-preserving technologies.</p>
          </div>
        </div>
      </div>
      <div
        className={`p-4 rounded-lg border ${
          requestData.privacyRequirements.differentialPrivacy
            ? 'border-blue-200 bg-blue-50 dark:border-blue-800 dark:bg-blue-900/20'
            : 'border-gray-200 dark:border-gray-700'
        }`}
      >
        <div className="flex items-start">
          <input
            id="differentialPrivacy"
            type="checkbox"
            checked={requestData.privacyRequirements.differentialPrivacy}
            onChange={(e) => handlePrivacyRequirementChange('differentialPrivacy', e.target.checked)}
            className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded dark:border-gray-700 dark:bg-gray-800"
          />
          <label htmlFor="differentialPrivacy" className="ml-3 block text-sm font-medium text-gray-700 dark:text-gray-300">
            Differential Privacy
          </label>
          {requestData.privacyRequirements.differentialPrivacy && (
            <div className="ml-3">
              <label htmlFor="privacyBudget" className="block text-xs font-medium text-gray-700 dark:text-gray-300">
                Privacy Budget (ε): {requestData.privacyRequirements.privacyBudget.toFixed(1)}
              </label>
              <input
                type="range"
                id="privacyBudget"
                min="0.1"
                max="10"
                step="0.1"
                value={requestData.privacyRequirements.privacyBudget}
                onChange={(e) => handlePrivacyRequirementChange('privacyBudget', parseFloat(e.target.value))}
                className="mt-1 w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer dark:bg-gray-700"
              />
              <div className="flex justify-between text-xs text-gray-500 dark:text-gray-400">
                <span>More Private</span>
                <span>More Accurate</span>
              </div>
            </div>
          )}
        </div>
      </div>
      <div
        className={`p-4 rounded-lg border ${
          requestData.privacyRequirements.secureMpc
            ? 'border-purple-200 bg-purple-50 dark:border-purple-800 dark:bg-purple-900/20'
            : 'border-gray-200 dark:border-gray-700'
        }`}
      >
        <div className="flex items-start">
          <input
            id="secureMpc"
            type="checkbox"
            checked={requestData.privacyRequirements.secureMpc}
            onChange={(e) => handlePrivacyRequirementChange('secureMpc', e.target.checked)}
            className="h-4 w-4 text-purple-600 focus:ring-purple-500 border-gray-300 rounded dark:border-gray-700 dark:bg-gray-800"
          />
          <label htmlFor="secureMpc" className="ml-3 block text-sm font-medium text-gray-700 dark:text-gray-300">
            Secure Multi-Party Computation
          </label>
        </div>
      </div>
      <div
        className={`p-4 rounded-lg border ${
          requestData.privacyRequirements.zkp
            ? 'border-yellow-200 bg-yellow-50 dark:border-yellow-800 dark:bg-yellow-900/20'
            : 'border-gray-200 dark:border-gray-700'
        }`}
      >
        <div className="flex items-start">
          <input
            id="zkp"
            type="checkbox"
            checked={requestData.privacyRequirements.zkp}
            onChange={(e) => handlePrivacyRequirementChange('zkp', e.target.checked)}
            className="h-4 w-4 text-yellow-600 focus:ring-yellow-500 border-gray-300 rounded dark:border-gray-700 dark:bg-gray-800"
          />
          <label htmlFor="zkp" className="ml-3 block text-sm font-medium text-gray-700 dark:text-gray-300">
            Zero-Knowledge Proofs
          </label>
        </div>
      </div>
      <div
        className={`p-4 rounded-lg border ${
          requestData.privacyRequirements.federatedLearning
            ? 'border-green-200 bg-green-50 dark:border-green-800 dark:bg-green-900/20'
            : 'border-gray-200 dark:border-gray-700'
        }`}
      >
        <div className="flex items-start">
          <input
            id="federatedLearning"
            type="checkbox"
            checked={requestData.privacyRequirements.federatedLearning}
            onChange={(e) => handlePrivacyRequirementChange('federatedLearning', e.target.checked)}
            className="h-4 w-4 text-green-600 focus:ring-green-500 border-gray-300 rounded dark:border-gray-700 dark:bg-gray-800"
          />
          <label htmlFor="federatedLearning" className="ml-3 block text-sm font-medium text-gray-700 dark:text-gray-300">
            Federated Learning
          </label>
        </div>
      </div>
      {formErrors.privacyTechnology && (
        <div className="p-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded text-sm text-red-600 dark:text-red-400">
          <AlertTriangle className="inline-block h-4 w-4 mr-1" /> {formErrors.privacyTechnology}
        </div>
      )}
    </div>
  );

  const renderDataAccessPlanStep = () => (
    <div className="space-y-6">
      <div className="bg-blue-50 dark:bg-blue-900/20 p-4 rounded-lg">
        <div className="flex">
          <Database className="h-6 w-6 text-blue-500" />
          <div className="ml-3">
            <h3 className="text-sm font-medium text-blue-800 dark:text-blue-200">Data Access Plan</h3>
            <p className="mt-1 text-sm text-blue-700 dark:text-blue-300">Describe how you'll use the data and select operations.</p>
          </div>
        </div>
      </div>
      <div>
        <label htmlFor="dataUsageDescription" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
          Data Usage Description
        </label>
        <textarea
          id="dataUsageDescription"
          rows={3}
          className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-700 shadow-sm sm:text-sm dark:bg-gray-800 dark:text-white"
          value={requestData.dataUsageDescription}
          onChange={(e) => handleInputChange('dataUsageDescription', e.target.value)}
          placeholder="Describe your specific data needs and analysis methods."
        />
      </div>
      {dataset?.allowedOperations?.length > 0 && (
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
            Required Operations <span className="text-red-500">*</span>
          </label>
          <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
            <div className="space-y-3">
              {dataset.allowedOperations.map((operation) => (
                <div key={operation.id} className="flex items-start">
                  <div className="flex items-center h-5">
                    <input
                      id={`operation-${operation.id}`}
                      type="checkbox"
                      className="focus:ring-blue-500 h-4 w-4 text-blue-600 border-gray-300 rounded dark:border-gray-700 dark:bg-gray-800"
                      checked={requestData.allowedOperations.includes(operation.id)}
                      onChange={() => toggleAllowedOperation(operation.id)}
                    />
                  </div>
                  <div className="ml-3">
                    <label
                      htmlFor={`operation-${operation.id}`}
                      className="font-medium text-gray-700 dark:text-gray-300"
                    >
                      {operation.name}
                    </label>
                    <p className="text-sm text-gray-500 dark:text-gray-400">{operation.description}</p>
                    {operation.privacyImpact && (
                      <div className="mt-1 text-xs text-yellow-600 dark:text-yellow-400 flex items-center">
                        <Shield className="h-3.5 w-3.5 mr-1" />
                        Privacy Impact: {operation.privacyImpact}
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
            {formErrors.allowedOperations && (
              <p className="mt-3 text-sm text-red-600 dark:text-red-400">{formErrors.allowedOperations}</p>
            )}
          </div>
        </div>
      )}
      {requestData.userFields.length > 0 && (
        <div>
          <h3 className="text-sm font-medium text-gray-900 dark:text-white mb-3">Required Information</h3>
          <div className="space-y-4 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
            {requestData.userFields.map((field) => (
              <div key={field.id}>
                <label
                  htmlFor={`field-${field.id}`}
                  className="block text-sm font-medium text-gray-700 dark:text-gray-300"
                >
                  {field.name} {field.required && <span className="text-red-500">*</span>}
                </label>
                <input
                  type="text"
                  id={`field-${field.id}`}
                  className={`mt-1 block w-full rounded-md shadow-sm sm:text-sm ${
                    formErrors[`userField_${field.id}`]
                      ? 'border-red-300 focus:ring-red-500 focus:border-red-500'
                      : 'border-gray-300 dark:border-gray-700 focus:ring-blue-500 focus:border-blue-500'
                  } dark:bg-gray-800 dark:text-white`}
                  value={field.value}
                  onChange={(e) => handleUserFieldChange(field.id, e.target.value)}
                  placeholder={field.placeholder || `Enter ${field.name}`}
                />
                {field.description && (
                  <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">{field.description}</p>
                )}
                {formErrors[`userField_${field.id}`] && (
                  <p className="mt-1 text-sm text-red-600 dark:text-red-400">{formErrors[`userField_${field.id}`]}</p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
      {dataset?.additionalRequirements && (
        <div className="bg-yellow-50 dark:bg-yellow-900/20 p-4 rounded-lg">
          <div className="flex">
            <AlertTriangle className="h-6 w-6 text-yellow-500" />
            <div className="ml-3">
              <h3 className="text-sm font-medium text-yellow-800 dark:text-yellow-200">Additional Requirements</h3>
              <div className="mt-1 text-sm text-yellow-700 dark:text-yellow-300">
                <p>{dataset.additionalRequirements}</p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );

  const renderReviewStep = () => (
    <div className="space-y-6">
      <div className="bg-green-50 dark:bg-green-900/20 p-4 rounded-lg">
        <div className="flex">
          <CheckCircle className="h-6 w-6 text-green-500" />
          <div className="ml-3">
            <h3 className="text-sm font-medium text-green-800 dark:text-green-200">Review Your Request</h3>
            <p className="mt-1 text-sm text-green-700 dark:text-green-300">
              Please review your access request details carefully before submission.
            </p>
          </div>
        </div>
      </div>
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Purpose & Project</h3>
        <dl className="grid grid-cols-1 gap-x-4 gap-y-6 sm:grid-cols-2">
          <div>
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Organization</dt>
            <dd className="mt-1 text-sm text-gray-900 dark:text-white">{requestData.organization}</dd>
          </div>
          <div>
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Project Name</dt>
            <dd className="mt-1 text-sm text-gray-900 dark:text-white">{requestData.projectName}</dd>
          </div>
          <div className="sm:col-span-2">
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Access Purpose</dt>
            <dd className="mt-1 text-sm text-gray-900 dark:text-white">{requestData.purpose}</dd>
          </div>
        </dl>
      </div>
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Privacy Requirements</h3>
        <ul className="space-y-2">
          {Object.entries(requestData.privacyRequirements).map(
            ([key, value]) =>
              value && (
                <li key={key} className="flex items-center">
                  {getPrivacyTechnologyIcon(key)}
                  <span className="ml-2 text-sm text-gray-900 dark:text-white">
                    {key.replace(/([A-Z])/g, ' $1').replace(/^./, (str) => str.toUpperCase())}
                  </span>
                </li>
              )
          )}
        </ul>
      </div>
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Data Access Plan</h3>
        <dl className="grid grid-cols-1 gap-x-4 gap-y-6">
          <div>
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Data Usage Description</dt>
            <dd className="mt-1 text-sm text-gray-900 dark:text-white">{requestData.dataUsageDescription}</dd>
          </div>
          {requestData.allowedOperations.length > 0 && (
            <div>
              <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Requested Operations</dt>
              <dd className="mt-1 text-sm text-gray-900 dark:text-white">{requestData.allowedOperations.join(', ')}</dd>
            </div>
          )}
        </dl>
      </div>
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Terms and Consent</h3>
        <div className="flex items-center">
          <input
            id="termsAgreed"
            type="checkbox"
            checked={requestData.termsAgreed}
            onChange={(e) => handleInputChange('termsAgreed', e.target.checked)}
            className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded dark:border-gray-700 dark:bg-gray-800"
          />
          <label htmlFor="termsAgreed" className="ml-3 block text-sm font-medium text-gray-700 dark:text-gray-300">
            Terms Agreement
          </label>
          {formErrors.termsAgreed && (
            <p className="ml-3 text-sm text-red-600 dark:text-red-400">{formErrors.termsAgreed}</p>
          )}
        </div>
        <div className="flex items-center mt-4">
          <input
            id="privacyConsent"
            type="checkbox"
            checked={requestData.privacyConsent}
            onChange={(e) => handleInputChange('privacyConsent', e.target.checked)}
            className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded dark:border-gray-700 dark:bg-gray-800"
          />
          <label htmlFor="privacyConsent" className="ml-3 block text-sm font-medium text-gray-700 dark:text-gray-300">
            Privacy Consent
          </label>
          {formErrors.privacyConsent && (
            <p className="ml-3 text-sm text-red-600 dark:text-red-400">{formErrors.privacyConsent}</p>
          )}
        </div>
      </div>
    </div>
  );

  // **Main Render**
  return (
    <div className={`access-request-container ${className}`} {...props}>
      <div className="mb-6">
        <h2 className="text-xl font-bold text-gray-900 dark:text-white">Request Dataset Access</h2>
        {dataset && (
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            Requesting access to <span className="font-medium text-gray-900 dark:text-white">{dataset.name}</span>
          </p>
        )}
      </div>
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
      {isLoading && !dataset ? (
        <div className="py-16 flex justify-center">
          <div className="animate-spin rounded-full h-10 w-10 border-4 border-blue-500 border-t-transparent"></div>
        </div>
      ) : (
        <>
          <div className="mb-8">
            <div className="relative">
              <div className="overflow-hidden h-2 flex rounded-full bg-gray-200 dark:bg-gray-700">
                <div
                  className="bg-blue-500 transition-all duration-500 ease-in-out"
                  style={{ width: `${(currentStep + 1) * 25}%` }}
                ></div>
              </div>
              <div className="flex justify-between mt-2 text-xs text-gray-600 dark:text-gray-400">
                <div className={currentStep >= 0 ? 'text-blue-600 dark:text-blue-400 font-medium' : ''}>Purpose</div>
                <div className={currentStep >= 1 ? 'text-blue-600 dark:text-blue-400 font-medium' : ''}>Privacy</div>
                <div className={currentStep >= 2 ? 'text-blue-600 dark:text-blue-400 font-medium' : ''}>Data Access</div>
                <div className={currentStep >= 3 ? 'text-blue-600 dark:text-blue-400 font-medium' : ''}>Review</div>
              </div>
            </div>
          </div>
          <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
            {renderStep()}
            <div className="mt-8 flex justify-between">
              <Button variant="secondary" onClick={handlePreviousStep}>
                {currentStep === 0 ? 'Cancel' : 'Previous'}
              </Button>
              <Button variant="primary" onClick={handleNextStep}>
                {currentStep === 3 ? 'Submit Request' : 'Next'}
              </Button>
            </div>
          </div>
        </>
      )}
      <Modal
        isOpen={showConfirmModal}
        onClose={() => setShowConfirmModal(false)}
        title="Confirm Access Request"
        size="medium"
      >
        <div className="space-y-4">
          <div className="bg-blue-50 dark:bg-blue-900/20 p-4 rounded-lg">
            <div className="flex">
              <Shield className="h-6 w-6 text-blue-500" />
              <div className="ml-3">
                <h3 className="text-sm font-medium text-blue-800 dark:text-blue-200">Privacy-Preserving Access Request</h3>
                <p className="mt-1 text-sm text-blue-700 dark:text-blue-300">
                  You are requesting privacy-preserving access to <span className="font-medium">{dataset?.name}</span>.
                  The data owner will review your request.
                </p>
              </div>
            </div>
          </div>
          <p className="text-gray-700 dark:text-gray-300">Are you sure you want to submit this access request?</p>
          <div className="flex justify-end space-x-3 pt-4">
            <Button variant="secondary" onClick={() => setShowConfirmModal(false)}>
              Cancel
            </Button>
            <Button variant="primary" onClick={handleSubmitRequest} isLoading={isLoading}>
              Submit Request
            </Button>
          </div>
        </div>
      </Modal>
      <Modal
        isOpen={requestStatus === 'success'}
        onClose={() => {
          setRequestStatus(null);
          if (onRequestSubmitted) onRequestSubmitted();
        }}
        title="Request Submitted"
        variant="success"
      >
        <div className="space-y-4">
          <div className="flex items-center justify-center py-4">
            <div className="rounded-full bg-green-100 dark:bg-green-900 p-4">
              <CheckCircle className="h-12 w-12 text-green-500" />
            </div>
          </div>
          <p className="text-center text-gray-700 dark:text-gray-300">
            Your access request has been successfully submitted. The data owner will review your request.
          </p>
          <div className="flex justify-center pt-4">
            <Button
              variant="primary"
              onClick={() => {
                setRequestStatus(null);
                if (onRequestSubmitted) onRequestSubmitted();
              }}
            >
              Close
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
};

AccessRequest.propTypes = {
  datasetId: PropTypes.string.isRequired,
  onRequestSubmitted: PropTypes.func,
  onCancel: PropTypes.func,
  className: PropTypes.string,
};

export default AccessRequest;
