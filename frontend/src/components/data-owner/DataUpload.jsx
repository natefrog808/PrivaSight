/**
 * DataUpload Component
 * 
 * A component for uploading and managing data in the PrivaSight platform.
 * Supports various file formats, encryption, privacy settings, and metadata.
 */

import React, { useState, useRef, useCallback, useEffect } from 'react';
import PropTypes from 'prop-types';
import { useDropzone } from 'react-dropzone';
import { useDataVault } from '../../hooks/useDataVault';
import { usePrivacyLayer } from '../../hooks/usePrivacyLayer';

// Icons
import { 
  UploadCloud, 
  File, 
  FilePlus, 
  FileText, 
  FileSpreadsheet,
  Shield, 
  Lock, 
  AlertTriangle,
  CheckCircle,
  X
} from '../icons';

// Components (assumed to be available in your project)
import Modal from '../common/Modal';
import Button from '../common/Button';

const FileTypeIcons = {
  'csv': <FileSpreadsheet className="w-8 h-8 text-green-500" />,
  'xlsx': <FileSpreadsheet className="w-8 h-8 text-blue-500" />,
  'json': <FileText className="w-8 h-8 text-yellow-500" />,
  'default': <File className="w-8 h-8 text-gray-400" />
};

const DataUpload = ({
  // Callbacks
  onUploadComplete,
  onUploadError,
  onCancel,
  
  // Configuration
  allowedFileTypes = ['.csv', '.xlsx', '.json'],
  maxFileSize = 50 * 1024 * 1024, // 50MB
  enableEncryption = true,
  showMetadataForm = true,
  
  // Data vault settings
  dataVaultId,
  createNewVault = false,
  
  // Privacy settings
  defaultPrivacySettings = {
    enableDifferentialPrivacy: true,
    enableFederatedLearning: false,
    enableSecureMpc: true,
    enableZkp: true,
    privacyBudget: 1.0
  },
  
  // UI Configuration
  className = '',
  
  // Additional props
  ...props
}) => {
  // **State**
  const [files, setFiles] = useState([]);
  const [uploadProgress, setUploadProgress] = useState({});
  const [isUploading, setIsUploading] = useState(false);
  const [privacySettings, setPrivacySettings] = useState(defaultPrivacySettings);
  const [metadata, setMetadata] = useState({
    title: '',
    description: '',
    tags: [],
    category: '',
    isPublic: false,
    licenseType: 'private'
  });
  const [currentStep, setCurrentStep] = useState(0);
  
  // **Refs**
  const fileInputRef = useRef(null);
  
  // **Custom Hooks**
  const { uploadToVault, createVault } = useDataVault();
  const { encryptData, applyPrivacyTransformations } = usePrivacyLayer();
  
  // **Dropzone Configuration**
  const { getRootProps, getInputProps, isDragActive, isDragReject } = useDropzone({
    accept: allowedFileTypes.reduce((acc, type) => {
      const mimeType = getMimeType(type);
      return { ...acc, [mimeType]: [type] };
    }, {}),
    maxSize: maxFileSize,
    onDrop: acceptedFiles => {
      const newFiles = acceptedFiles.map(file => Object.assign(file, {
        preview: URL.createObjectURL(file),
        id: Math.random().toString(36).substring(2),
        status: 'ready' // ready, uploading, success, error
      }));
      setFiles(prevFiles => [...prevFiles, ...newFiles]);
    },
    onDropRejected: rejectedFiles => {
      const errorMessage = rejectedFiles.map(({ file, errors }) => {
        return `${file.name}: ${errors.map(e => e.message).join(', ')}`;
      }).join('\n');
      onUploadError?.(errorMessage);
    }
  });
  
  // **Helper Functions**
  const getMimeType = (extension) => {
    const mapping = {
      '.csv': 'text/csv',
      '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      '.json': 'application/json'
    };
    return mapping[extension] || 'application/octet-stream';
  };
  
  const getFileIcon = (fileName) => {
    const extension = fileName.split('.').pop().toLowerCase();
    return FileTypeIcons[extension] || FileTypeIcons.default;
  };
  
  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };
  
  // **Event Handlers**
  const handleBrowseClick = () => {
    fileInputRef.current?.click();
  };
  
  const handleRemoveFile = useCallback((fileId) => {
    setFiles(prevFiles => {
      const fileToRemove = prevFiles.find(file => file.id === fileId);
      if (fileToRemove) URL.revokeObjectURL(fileToRemove.preview);
      return prevFiles.filter(file => file.id !== fileId);
    });
  }, []);
  
  const handleTagInputKeyDown = (e) => {
    if (e.key === 'Enter' && e.target.value) {
      e.preventDefault();
      if (!metadata.tags.includes(e.target.value)) {
        setMetadata(prev => ({ ...prev, tags: [...prev.tags, e.target.value] }));
      }
      e.target.value = '';
    }
  };
  
  const handleRemoveTag = (tagToRemove) => {
    setMetadata(prev => ({ ...prev, tags: prev.tags.filter(tag => tag !== tagToRemove) }));
  };
  
  const handlePrivacySettingChange = (setting, value) => {
    setPrivacySettings(prev => ({ ...prev, [setting]: value }));
  };
  
  const handleUpload = async () => {
    if (files.length === 0) return;
    setIsUploading(true);
    const updatedFiles = [...files];
    
    try {
      // Create a new vault if needed
      let vaultId = dataVaultId;
      if (createNewVault) {
        vaultId = await createVault({ ...metadata, privacySettings });
      }
      
      // Process and upload each file
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        updatedFiles[i] = { ...file, status: 'uploading' };
        setFiles([...updatedFiles]);
        setUploadProgress(prev => ({ ...prev, [file.id]: 0 }));
        
        const fileData = await readFileAsArrayBuffer(file);
        let processedData = fileData;
        if (Object.values(privacySettings).some(setting => setting === true)) {
          processedData = await applyPrivacyTransformations(fileData, privacySettings);
        }
        let finalData = processedData;
        if (enableEncryption) {
          finalData = await encryptData(processedData);
        }
        await uploadToVault(vaultId, finalData, file.name, {
          onProgress: (progress) => {
            setUploadProgress(prev => ({ ...prev, [file.id]: progress }));
          }
        });
        updatedFiles[i] = { ...file, status: 'success' };
        setFiles([...updatedFiles]);
      }
      
      onUploadComplete?.({ vaultId, files: updatedFiles, metadata, privacySettings });
      setTimeout(() => {
        setFiles([]);
        setUploadProgress({});
        setMetadata({ title: '', description: '', tags: [], category: '', isPublic: false, licenseType: 'private' });
        setCurrentStep(0);
      }, 2000);
    } catch (error) {
      updatedFiles.forEach(file => {
        if (file.status === 'uploading') file.status = 'error';
      });
      setFiles([...updatedFiles]);
      onUploadError?.(error.message);
    } finally {
      setIsUploading(false);
    }
  };
  
  const readFileAsArrayBuffer = (file) => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = reject;
      reader.readAsArrayBuffer(file);
    });
  };
  
  // **Step Configuration**
  const steps = [
    { 
      title: 'Select Data Files', 
      component: <FileSelection />,
      canProceed: files.length > 0
    },
    { 
      title: showMetadataForm ? 'Add Metadata' : 'Configure Privacy Settings', 
      component: showMetadataForm ? <MetadataForm /> : <PrivacySettings />,
      canProceed: !showMetadataForm || (metadata.title && metadata.description)
    },
    {
      title: showMetadataForm ? 'Configure Privacy Settings' : 'Review & Upload',
      component: showMetadataForm ? <PrivacySettings /> : <ReviewAndUpload />,
      canProceed: true
    },
    {
      title: showMetadataForm ? 'Review & Upload' : null,
      component: showMetadataForm ? <ReviewAndUpload /> : null,
      canProceed: true
    }
  ].filter(step => step.title !== null);
  
  const nextStep = () => {
    if (currentStep < steps.length - 1) {
      setCurrentStep(currentStep + 1);
    } else {
      handleUpload();
    }
  };
  
  const prevStep = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    } else {
      onCancel?.();
    }
  };
  
  // **Step Components**
  function FileSelection() {
    return (
      <div className="space-y-6">
        <div 
          {...getRootProps()} 
          className={`
            border-2 border-dashed rounded-lg p-8 text-center
            ${isDragActive ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20' : 'border-gray-300 dark:border-gray-700'} 
            ${isDragReject ? 'border-red-500 bg-red-50 dark:bg-red-900/20' : ''}
            transition-all duration-200 cursor-pointer
          `}
        >
          <input {...getInputProps()} ref={fileInputRef} />
          <UploadCloud className="mx-auto h-12 w-12 text-gray-400" />
          <p className="mt-2 text-sm font-medium text-gray-900 dark:text-white">
            {isDragActive ? 'Drop files here...' : 'Drag & drop files here'}
          </p>
          <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
            or <button type="button" className="text-blue-600 dark:text-blue-400 hover:underline" onClick={handleBrowseClick}>browse files</button>
          </p>
          <p className="mt-2 text-xs text-gray-500 dark:text-gray-400">
            Allowed file types: {allowedFileTypes.join(', ')}
          </p>
          <p className="text-xs text-gray-500 dark:text-gray-400">
            Maximum file size: {formatFileSize(maxFileSize)}
          </p>
        </div>
        {files.length > 0 && (
          <div>
            <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-2">Selected Files</h4>
            <div className="space-y-2">
              {files.map((file) => (
                <div key={file.id} className="flex items-center p-3 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg shadow-sm">
                  {getFileIcon(file.name)}
                  <div className="ml-3 flex-1 min-w-0">
                    <p className="text-sm font-medium text-gray-900 dark:text-white truncate">{file.name}</p>
                    <p className="text-xs text-gray-500 dark:text-gray-400">
                      {formatFileSize(file.size)}
                      {file.status === 'uploading' && <span className="ml-2">Uploading: {uploadProgress[file.id] || 0}%</span>}
                      {file.status === 'success' && <span className="ml-2 text-green-500 flex items-center"><CheckCircle className="w-3 h-3 mr-1" /> Uploaded</span>}
                      {file.status === 'error' && <span className="ml-2 text-red-500 flex items-center"><AlertTriangle className="w-3 h-3 mr-1" /> Error</span>}
                    </p>
                    {file.status === 'uploading' && (
                      <div className="w-full bg-gray-200 rounded-full h-1 mt-1 dark:bg-gray-700">
                        <div className="bg-blue-600 h-1 rounded-full" style={{ width: `${uploadProgress[file.id] || 0}%` }}></div>
                      </div>
                    )}
                  </div>
                  {file.status !== 'uploading' && (
                    <button type="button" onClick={() => handleRemoveFile(file.id)} className="text-gray-400 hover:text-gray-500 dark:hover:text-gray-300" aria-label="Remove file">
                      <X className="w-5 h-5" />
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  }
  
  function MetadataForm() {
    return (
      <div className="space-y-4">
        <p className="text-sm text-gray-600 dark:text-gray-400">Add metadata to help organize and discover your data.</p>
        <div className="space-y-4">
          <div>
            <label htmlFor="title" className="block text-sm font-medium text-gray-700 dark:text-gray-300">Title <span className="text-red-500">*</span></label>
            <input type="text" id="title" value={metadata.title} onChange={(e) => setMetadata({ ...metadata, title: e.target.value })} className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-700 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm dark:bg-gray-700 dark:text-white" placeholder="e.g., Customer Demographics 2024" required />
          </div>
          <div>
            <label htmlFor="description" className="block text-sm font-medium text-gray-700 dark:text-gray-300">Description <span className="text-red-500">*</span></label>
            <textarea id="description" value={metadata.description} onChange={(e) => setMetadata({ ...metadata, description: e.target.value })} rows={3} className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-700 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm dark:bg-gray-700 dark:text-white" placeholder="Describe the contents and purpose of this data..." required />
          </div>
          <div>
            <label htmlFor="category" className="block text-sm font-medium text-gray-700 dark:text-gray-300">Category</label>
            <select id="category" value={metadata.category} onChange={(e) => setMetadata({ ...metadata, category: e.target.value })} className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-700 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm dark:bg-gray-700 dark:text-white">
              <option value="">Select a category</option>
              <option value="healthcare">Healthcare</option>
              <option value="finance">Finance</option>
              <option value="marketing">Marketing</option>
              <option value="sales">Sales</option>
              <option value="hr">Human Resources</option>
              <option value="research">Research</option>
              <option value="operations">Operations</option>
              <option value="other">Other</option>
            </select>
          </div>
          <div>
            <label htmlFor="tags" className="block text-sm font-medium text-gray-700 dark:text-gray-300">Tags</label>
            <div className="mt-1">
              <input type="text" id="tags" onKeyDown={handleTagInputKeyDown} className="block w-full rounded-md border-gray-300 dark:border-gray-700 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm dark:bg-gray-700 dark:text-white" placeholder="Type and press Enter to add tags" />
            </div>
            {metadata.tags.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-2">
                {metadata.tags.map((tag) => (
                  <span key={tag} className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-800 dark:text-blue-100">
                    {tag}
                    <button type="button" onClick={() => handleRemoveTag(tag)} className="ml-1.5 h-4 w-4 rounded-full inline-flex items-center justify-center text-blue-400 hover:text-blue-500 focus:outline-none focus:text-blue-500">
                      <span className="sr-only">Remove tag {tag}</span>
                      <X className="h-3 w-3" />
                    </button>
                  </span>
                ))}
              </div>
            )}
          </div>
          <div>
            <div className="flex items-start">
              <div className="flex items-center h-5">
                <input id="isPublic" type="checkbox" checked={metadata.isPublic} onChange={(e) => setMetadata({ ...metadata, isPublic: e.target.checked })} className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded dark:border-gray-700 dark:bg-gray-700" />
              </div>
              <div className="ml-3 text-sm">
                <label htmlFor="isPublic" className="font-medium text-gray-700 dark:text-gray-300">Make data discoverable</label>
                <p className="text-gray-500 dark:text-gray-400">Allow other users to discover this data (access still requires your approval)</p>
              </div>
            </div>
          </div>
          <div>
            <label htmlFor="licenseType" className="block text-sm font-medium text-gray-700 dark:text-gray-300">License Type</label>
            <select id="licenseType" value={metadata.licenseType} onChange={(e) => setMetadata({ ...metadata, licenseType: e.target.value })} className="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-700 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm dark:bg-gray-700 dark:text-white">
              <option value="private">Private (No License)</option>
              <option value="cc-by">Creative Commons (CC BY)</option>
              <option value="cc-by-sa">Creative Commons (CC BY-SA)</option>
              <option value="cc-by-nc">Creative Commons (CC BY-NC)</option>
              <option value="mit">MIT License</option>
              <option value="apache">Apache License 2.0</option>
              <option value="custom">Custom License</option>
            </select>
          </div>
        </div>
      </div>
    );
  }
  
  function PrivacySettings() {
    return (
      <div className="space-y-4">
        <div className="bg-blue-50 dark:bg-blue-900/20 p-4 rounded-lg">
          <div className="flex items-start">
            <Shield className="h-6 w-6 text-blue-600 dark:text-blue-400 mt-0.5" />
            <div className="ml-3">
              <h3 className="text-sm font-medium text-blue-800 dark:text-blue-200">Privacy Protection</h3>
              <p className="mt-1 text-sm text-blue-700 dark:text-blue-300">Configure privacy-preserving technologies to protect your data while enabling secure analytics.</p>
            </div>
          </div>
        </div>
        <div className="space-y-3">
          {/* Differential Privacy */}
          <div className="flex items-start p-3 border border-gray-200 dark:border-gray-700 rounded-lg">
            <div className="flex items-center h-5">
              <input id="enableDifferentialPrivacy" type="checkbox" checked={privacySettings.enableDifferentialPrivacy} onChange={(e) => handlePrivacySettingChange('enableDifferentialPrivacy', e.target.checked)} className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded dark:border-gray-700 dark:bg-gray-700" />
            </div>
            <div className="ml-3 text-sm">
              <label htmlFor="enableDifferentialPrivacy" className="font-medium text-gray-900 dark:text-white">Differential Privacy</label>
              <p className="text-gray-500 dark:text-gray-400">Adds mathematical noise to protect individual data points while enabling accurate aggregate analysis.</p>
              {privacySettings.enableDifferentialPrivacy && (
                <div className="mt-3">
                  <label htmlFor="privacyBudget" className="block text-xs font-medium text-gray-700 dark:text-gray-300">Privacy Budget (ε): {privacySettings.privacyBudget.toFixed(1)}</label>
                  <input type="range" id="privacyBudget" min="0.1" max="10" step="0.1" value={privacySettings.privacyBudget} onChange={(e) => handlePrivacySettingChange('privacyBudget', parseFloat(e.target.value))} className="mt-1 w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer dark:bg-gray-700" />
                  <div className="flex justify-between text-xs text-gray-500 dark:text-gray-400">
                    <span>More Private</span>
                    <span>More Accurate</span>
                  </div>
                </div>
              )}
            </div>
          </div>
          {/* Federated Learning */}
          <div className="flex items-start p-3 border border-gray-200 dark:border-gray-700 rounded-lg">
            <div className="flex items-center h-5">
              <input id="enableFederatedLearning" type="checkbox" checked={privacySettings.enableFederatedLearning} onChange={(e) => handlePrivacySettingChange('enableFederatedLearning', e.target.checked)} className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded dark:border-gray-700 dark:bg-gray-700" />
            </div>
            <div className="ml-3 text-sm">
              <label htmlFor="enableFederatedLearning" className="font-medium text-gray-900 dark:text-white">Federated Learning</label>
              <p className="text-gray-500 dark:text-gray-400">Allows machine learning models to be trained across decentralized datasets without centralizing sensitive data.</p>
            </div>
          </div>
          {/* Secure MPC */}
          <div className="flex items-start p-3 border border-gray-200 dark:border-gray-700 rounded-lg">
            <div className="flex items-center h-5">
              <input id="enableSecureMpc" type="checkbox" checked={privacySettings.enableSecureMpc} onChange={(e) => handlePrivacySettingChange('enableSecureMpc', e.target.checked)} className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded dark:border-gray-700 dark:bg-gray-700" />
            </div>
            <div className="ml-3 text-sm">
              <label htmlFor="enableSecureMpc" className="font-medium text-gray-900 dark:text-white">Secure Multi-Party Computation</label>
              <p className="text-gray-500 dark:text-gray-400">Enables encrypted computations across multiple parties without exposing individual inputs.</p>
            </div>
          </div>
          {/* Zero-Knowledge Proofs */}
          <div className="flex items-start p-3 border border-gray-200 dark:border-gray-700 rounded-lg">
            <div className="flex items-center h-5">
              <input id="enableZkp" type="checkbox" checked={privacySettings.enableZkp} onChange={(e) => handlePrivacySettingChange('enableZkp', e.target.checked)} className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded dark:border-gray-700 dark:bg-gray-700" />
            </div>
            <div className="ml-3 text-sm">
              <label htmlFor="enableZkp" className="font-medium text-gray-900 dark:text-white">Zero-Knowledge Proofs</label>
              <p className="text-gray-500 dark:text-gray-400">Verifies data properties or computations without revealing the underlying data.</p>
            </div>
          </div>
        </div>
        <div className="p-3 border border-gray-200 dark:border-gray-700 rounded-lg">
          <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-2">Client-Side Encryption</h4>
          <div className="flex items-start">
            <div className="flex items-center h-5">
              <input id="enableEncryption" type="checkbox" checked={enableEncryption} disabled className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded dark:border-gray-700 dark:bg-gray-700 cursor-not-allowed" />
            </div>
            <div className="ml-3 text-sm">
              <label htmlFor="enableEncryption" className="font-medium text-gray-900 dark:text-white flex items-center">
                End-to-End Encryption
                <span className="ml-2 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-800 dark:text-green-100">Required</span>
              </label>
              <p className="text-gray-500 dark:text-gray-400">Encrypts data on your device before upload. Only you and authorized users with the appropriate keys can access the original data.</p>
            </div>
          </div>
        </div>
      </div>
    );
  }
  
  function ReviewAndUpload() {
    return (
      <div className="space-y-6">
        <div className="bg-green-50 dark:bg-green-900/20 p-4 rounded-lg">
          <div className="flex">
            <CheckCircle className="h-6 w-6 text-green-500" />
            <div className="ml-3">
              <h3 className="text-sm font-medium text-green-800 dark:text-green-200">Ready to Upload</h3>
              <p className="mt-1 text-sm text-green-700 dark:text-green-300">Your files are ready to be uploaded with the selected privacy settings.</p>
            </div>
          </div>
        </div>
        <div>
          <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-2">Files to Upload</h4>
          <div className="border border-gray-200 dark:border-gray-700 rounded-lg divide-y divide-gray-200 dark:divide-gray-700">
            {files.map((file) => (
              <div key={file.id} className="flex items-center p-4">
                {getFileIcon(file.name)}
                <div className="ml-3 flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-900 dark:text-white truncate">{file.name}</p>
                  <p className="text-xs text-gray-500 dark:text-gray-400">{formatFileSize(file.size)}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
        {showMetadataForm && (
          <div>
            <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-2">Data Metadata</h4>
            <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
              <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-2">
                <div className="sm:col-span-2">
                  <dt className="text-xs font-medium text-gray-500 dark:text-gray-400">Title</dt>
                  <dd className="mt-1 text-sm text-gray-900 dark:text-white">{metadata.title || "—"}</dd>
                </div>
                <div className="sm:col-span-2">
                  <dt className="text-xs font-medium text-gray-500 dark:text-gray-400">Description</dt>
                  <dd className="mt-1 text-sm text-gray-900 dark:text-white">{metadata.description || "—"}</dd>
                </div>
                <div>
                  <dt className="text-xs font-medium text-gray-500 dark:text-gray-400">Category</dt>
                  <dd className="mt-1 text-sm text-gray-900 dark:text-white">{metadata.category || "—"}</dd>
                </div>
                <div>
                  <dt className="text-xs font-medium text-gray-500 dark:text-gray-400">License</dt>
                  <dd className="mt-1 text-sm text-gray-900 dark:text-white">{metadata.licenseType}</dd>
                </div>
                <div className="sm:col-span-2">
                  <dt className="text-xs font-medium text-gray-500 dark:text-gray-400">Tags</dt>
                  <dd className="mt-1">
                    {metadata.tags.length > 0 ? (
                      <div className="flex flex-wrap gap-1">
                        {metadata.tags.map((tag) => (
                          <span key={tag} className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-800 dark:text-blue-100">{tag}</span>
                        ))}
                      </div>
                    ) : (
                      <span className="text-sm text-gray-500 dark:text-gray-400">No tags</span>
                    )}
                  </dd>
                </div>
                <div className="sm:col-span-2">
                  <dt className="text-xs font-medium text-gray-500 dark:text-gray-400">Discoverability</dt>
                  <dd className="mt-1 text-sm text-gray-900 dark:text-white">{metadata.isPublic ? "Discoverable by other users" : "Private (not discoverable)"}</dd>
                </div>
              </dl>
            </div>
          </div>
        )}
        <div>
          <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-2">Privacy Protections</h4>
          <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
            <ul className="space-y-2">
              <li className="flex items-center">
                <div className={`flex-shrink-0 w-5 h-5 ${privacySettings.enableDifferentialPrivacy ? 'text-green-500' : 'text-gray-300 dark:text-gray-600'}`}>
                  {privacySettings.enableDifferentialPrivacy ? <CheckCircle className="w-5 h-5" /> : <div className="w-5 h-5 border-2 border-gray-300 dark:border-gray-600 rounded-full"></div>}
                </div>
                <span className="ml-2 text-sm text-gray-900 dark:text-white">Differential Privacy</span>
                {privacySettings.enableDifferentialPrivacy && <span className="ml-1 text-xs text-gray-500 dark:text-gray-400">(ε = {privacySettings.privacyBudget.toFixed(1)})</span>}
              </li>
              <li className="flex items-center">
                <div className={`flex-shrink-0 w-5 h-5 ${privacySettings.enableFederatedLearning ? 'text-green-500' : 'text-gray-300 dark:text-gray-600'}`}>
                  {privacySettings.enableFederatedLearning ? <CheckCircle className="w-5 h-5" /> : <div className="w-5 h-5 border-2 border-gray-300 dark:border-gray-600 rounded-full"></div>}
                </div>
                <span className="ml-2 text-sm text-gray-900 dark:text-white">Federated Learning</span>
              </li>
              <li className="flex items-center">
                <div className={`flex-shrink-0 w-5 h-5 ${privacySettings.enableSecureMpc ? 'text-green-500' : 'text-gray-300 dark:text-gray-600'}`}>
                  {privacySettings.enableSecureMpc ? <CheckCircle className="w-5 h-5" /> : <div className="w-5 h-5 border-2 border-gray-300 dark:border-gray-600 rounded-full"></div>}
                </div>
                <span className="ml-2 text-sm text-gray-900 dark:text-white">Secure Multi-Party Computation</span>
              </li>
              <li className="flex items-center">
                <div className={`flex-shrink-0 w-5 h-5 ${privacySettings.enableZkp ? 'text-green-500' : 'text-gray-300 dark:text-gray-600'}`}>
                  {privacySettings.enableZkp ? <CheckCircle className="w-5 h-5" /> : <div className="w-5 h-5 border-2 border-gray-300 dark:border-gray-600 rounded-full"></div>}
                </div>
                <span className="ml-2 text-sm text-gray-900 dark:text-white">Zero-Knowledge Proofs</span>
              </li>
              <li className="flex items-center">
                <div className="flex-shrink-0 w-5 h-5 text-green-500">
                  <CheckCircle className="w-5 h-5" />
                </div>
                <span className="ml-2 text-sm text-gray-900 dark:text-white">End-to-End Encryption</span>
              </li>
            </ul>
          </div>
        </div>
        <div className="bg-yellow-50 dark:bg-yellow-900/20 p-4 rounded-lg">
          <div className="flex">
            <Lock className="h-6 w-6 text-yellow-500" />
            <div className="ml-3">
              <h3 className="text-sm font-medium text-yellow-800 dark:text-yellow-200">Encryption Key Security</h3>
              <p className="mt-1 text-sm text-yellow-700 dark:text-yellow-300">Your encryption keys are stored in your secure wallet. Make sure you have backed up your wallet - lost keys cannot be recovered and will result in permanent data loss.</p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // **Cleanup**
  useEffect(() => {
    return () => {
      files.forEach(file => URL.revokeObjectURL(file.preview));
    };
  }, [files]);

  // **Render**
  return (
    <div className={`space-y-6 ${className}`}>
      {/* Step Indicator */}
      <div className="flex justify-between mb-6">
        {steps.map((step, index) => (
          <div key={index} className={`flex-1 text-center ${index === currentStep ? 'text-blue-600 font-medium' : 'text-gray-500'}`}>
            {step.title}
          </div>
        ))}
      </div>
      {/* Current Step Component */}
      {steps[currentStep].component}
      {/* Navigation Buttons */}
      <div className="mt-6 flex justify-between">
        <Button variant="secondary" onClick={prevStep} disabled={isUploading}>
          {currentStep === 0 ? 'Cancel' : 'Back'}
        </Button>
        <Button variant="primary" onClick={nextStep} disabled={isUploading || !steps[currentStep].canProceed}>
          {currentStep === steps.length - 1 ? 'Upload' : 'Next'}
        </Button>
      </div>
    </div>
  );
};

// **PropTypes**
DataUpload.propTypes = {
  onUploadComplete: PropTypes.func,
  onUploadError: PropTypes.func,
  onCancel: PropTypes.func,
  allowedFileTypes: PropTypes.arrayOf(PropTypes.string),
  maxFileSize: PropTypes.number,
  enableEncryption: PropTypes.bool,
  showMetadataForm: PropTypes.bool,
  dataVaultId: PropTypes.string,
  createNewVault: PropTypes.bool,
  defaultPrivacySettings: PropTypes.shape({
    enableDifferentialPrivacy: PropTypes.bool,
    enableFederatedLearning: PropTypes.bool,
    enableSecureMpc: PropTypes.bool,
    enableZkp: PropTypes.bool,
    privacyBudget: PropTypes.number,
  }),
  className: PropTypes.string,
};

export default DataUpload;
