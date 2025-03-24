/**
 * Modal Component
 * 
 * A flexible modal dialog component for the PrivaSight platform.
 * Features animated transitions, backdrop, various sizes, and accessibility support.
 */

import React, { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import PropTypes from 'prop-types';
import { X } from '../icons';

const Modal = ({
  // Content
  children,
  title,
  description,
  
  // Control
  isOpen,
  onClose,
  closeOnEsc = true,
  closeOnOutsideClick = true,
  
  // Styling
  size = 'medium',
  position = 'center',
  variant = 'default',
  showCloseButton = true,
  
  // Header/Footer
  header,
  footer,
  hideHeader = false,
  
  // Transitions
  transitionDuration = 200,
  
  // Privacy features
  privacySensitive = false,
  
  // Accessibility
  ariaLabelledby,
  ariaDescribedby,
  
  // Additional props
  className = '',
  ...props
}) => {
  const [mounted, setMounted] = useState(false);
  const [transitioning, setTransitioning] = useState(false);
  
  const modalRef = useRef(null);
  const titleId = ariaLabelledby || 'modal-title';
  const descriptionId = ariaDescribedby || (description ? 'modal-description' : undefined);
  
  // Handle mounting the modal portal
  useEffect(() => {
    setMounted(true);
    return () => setMounted(false);
  }, []);
  
  // Handle transition effects and body overflow
  useEffect(() => {
    if (isOpen) {
      document.body.classList.add('overflow-hidden');
      setTransitioning(true);
      const timer = setTimeout(() => setTransitioning(false), transitionDuration);
      return () => clearTimeout(timer);
    } else {
      document.body.classList.remove('overflow-hidden');
    }
  }, [isOpen, transitionDuration]);
  
  // Handle ESC key to close modal
  useEffect(() => {
    if (!isOpen || !closeOnEsc) return;
    
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') onClose();
    };
    
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose, closeOnEsc]);
  
  // Focus modal when it opens for accessibility
  useEffect(() => {
    if (isOpen && modalRef.current) {
      modalRef.current.focus();
    }
  }, [isOpen]);
  
  // Handle clicks outside modal content
  const handleOutsideClick = (e) => {
    if (closeOnOutsideClick && e.target === e.currentTarget) {
      onClose();
    }
  };
  
  // Size classes
  const sizeClasses = {
    xs: 'max-w-xs',
    small: 'max-w-sm',
    medium: 'max-w-md',
    large: 'max-w-lg',
    xl: 'max-w-xl',
    '2xl': 'max-w-2xl',
    '3xl': 'max-w-3xl',
    '4xl': 'max-w-4xl',
    '5xl': 'max-w-5xl',
    full: 'max-w-full',
  };
  
  // Position classes
  const positionClasses = {
    center: 'items-center justify-center',
    top: 'items-start justify-center pt-16',
    'top-left': 'items-start justify-start p-4',
    'top-right': 'items-start justify-end p-4',
    'bottom-left': 'items-end justify-start p-4',
    'bottom-right': 'items-end justify-end p-4',
  };
  
  // Variant classes
  const variantClasses = {
    default: '',
    primary: 'border-l-4 border-blue-500',
    danger: 'border-l-4 border-red-500',
    warning: 'border-l-4 border-yellow-500',
    success: 'border-l-4 border-green-500',
    info: 'border-l-4 border-cyan-500',
    analytics: 'border-l-4 border-purple-500',
  };
  
  // Animation classes
  const animationClasses = transitioning
    ? 'opacity-0 scale-95'
    : 'opacity-100 scale-100';
  
  // Privacy classes
  const privacyClasses = privacySensitive
    ? 'border-purple-500 dark:border-purple-400'
    : '';
  
  // Modal content
  const modalContent = (
    <div
      className={`fixed inset-0 z-50 overflow-y-auto ${isOpen ? 'visible' : 'invisible'}`}
      role="dialog"
      aria-modal="true"
      aria-labelledby={titleId}
      aria-describedby={descriptionId}
      {...props}
    >
      {/* Backdrop */}
      <div 
        className={`fixed inset-0 bg-black transition-opacity duration-${transitionDuration} ${isOpen && !transitioning ? 'opacity-50' : 'opacity-0'}`}
        aria-hidden="true"
      ></div>
      
      {/* Modal container */}
      <div 
        className={`flex min-h-screen ${positionClasses[position]}`}
        onClick={handleOutsideClick}
      >
        {/* Modal box */}
        <div
          ref={modalRef}
          tabIndex={-1} // Make modal focusable
          className={`
            relative ${sizeClasses[size]} w-full 
            bg-white dark:bg-gray-800 
            rounded-lg shadow-xl border
            ${privacyClasses}
            ${variantClasses[variant]}
            ${animationClasses}
            transition-all duration-${transitionDuration}
            my-8 mx-auto
            ${className}
          `}
        >
          {!hideHeader && (
            <div className="flex items-start justify-between p-4 border-b dark:border-gray-700">
              {header || (
                <div>
                  {title && (
                    <h3 
                      id={titleId}
                      className="text-lg font-semibold text-gray-900 dark:text-white"
                    >
                      {title}
                    </h3>
                  )}
                  {description && (
                    <p 
                      id={descriptionId}
                      className="mt-1 text-sm text-gray-500 dark:text-gray-400"
                    >
                      {description}
                    </p>
                  )}
                </div>
              )}
              
              {showCloseButton && (
                <button
                  type="button"
                  className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500 rounded-md"
                  onClick={onClose}
                  aria-label="Close"
                >
                  <X className="w-5 h-5" />
                </button>
              )}
            </div>
          )}
          
          <div className="p-6">
            {children}
          </div>
          
          {footer && (
            <div className="px-6 py-4 border-t dark:border-gray-700 bg-gray-50 dark:bg-gray-900 rounded-b-lg">
              {footer}
            </div>
          )}
          
          {/* Privacy indicator */}
          {privacySensitive && (
            <div className="absolute -top-2 -right-2 w-4 h-4 bg-purple-500 rounded-full border-2 border-white dark:border-gray-800"></div>
          )}
        </div>
      </div>
    </div>
  );
  
  if (!mounted) return null;
  
  return createPortal(
    isOpen ? modalContent : null,
    document.getElementById('modal-root') || document.body
  );
};

Modal.propTypes = {
  children: PropTypes.node.isRequired,
  title: PropTypes.node,
  description: PropTypes.node,
  isOpen: PropTypes.bool.isRequired,
  onClose: PropTypes.func.isRequired,
  closeOnEsc: PropTypes.bool,
  closeOnOutsideClick: PropTypes.bool,
  size: PropTypes.oneOf(['xs', 'small', 'medium', 'large', 'xl', '2xl', '3xl', '4xl', '5xl', 'full']),
  position: PropTypes.oneOf(['center', 'top', 'top-left', 'top-right', 'bottom-left', 'bottom-right']),
  variant: PropTypes.oneOf(['default', 'primary', 'danger', 'warning', 'success', 'info', 'analytics']),
  showCloseButton: PropTypes.bool,
  header: PropTypes.node,
  footer: PropTypes.node,
  hideHeader: PropTypes.bool,
  transitionDuration: PropTypes.number,
  privacySensitive: PropTypes.bool,
  ariaLabelledby: PropTypes.string,
  ariaDescribedby: PropTypes.string,
  className: PropTypes.string,
};

/**
 * PrivacySettingsModal
 * A pre-configured modal for managing privacy settings.
 */
export const PrivacySettingsModal = ({ isOpen, onClose, settings, onSettingsChange, ...props }) => {
  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Privacy Settings"
      description="Configure your data privacy preferences"
      size="large"
      variant="analytics"
      privacySensitive={true}
      footer={
        <div className="flex justify-end space-x-3">
          <button 
            type="button"
            className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md shadow-sm hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-blue-500"
            onClick={onClose}
          >
            Cancel
          </button>
          <button 
            type="button"
            className="px-4 py-2 text-sm font-medium text-white bg-purple-600 border border-transparent rounded-md shadow-sm hover:bg-purple-700 focus:outline-none focus:ring-2 focus:ring-purple-500"
            onClick={() => {
              onClose();
            }}
          >
            Save Settings
          </button>
        </div>
      }
      {...props}
    >
      <div className="space-y-4">
        <p className="text-sm text-gray-600 dark:text-gray-400">
          PrivaSight utilizes advanced privacy-preserving technologies to protect your sensitive data
          while still enabling powerful analytics capabilities.
        </p>
        
        <div className="space-y-3">
          {settings.map((setting) => (
            <div key={setting.id} className="flex items-start justify-between p-3 border rounded-lg border-gray-200 dark:border-gray-700">
              <div>
                <h4 className="font-medium text-gray-900 dark:text-white">{setting.title}</h4>
                <p className="text-sm text-gray-500 dark:text-gray-400">{setting.description}</p>
              </div>
              <div className="ml-4">
                <label className="relative inline-flex items-center cursor-pointer">
                  <input 
                    type="checkbox" 
                    className="sr-only peer" 
                    checked={setting.enabled}
                    onChange={() => onSettingsChange(setting.id, !setting.enabled)}
                  />
                  <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-purple-300 dark:peer-focus:ring-purple-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-purple-600"></div>
                </label>
              </div>
            </div>
          ))}
        </div>
      </div>
    </Modal>
  );
};

PrivacySettingsModal.propTypes = {
  isOpen: PropTypes.bool.isRequired,
  onClose: PropTypes.func.isRequired,
  settings: PropTypes.arrayOf(
    PropTypes.shape({
      id: PropTypes.string.isRequired,
      title: PropTypes.string.isRequired,
      description: PropTypes.string,
      enabled: PropTypes.bool.isRequired,
    })
  ).isRequired,
  onSettingsChange: PropTypes.func.isRequired,
};

/**
 * DataVaultAccessModal
 * A pre-configured modal for managing data vault access requests.
 */
export const DataVaultAccessModal = ({ isOpen, onClose, vault, onGrantAccess, ...props }) => {
  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={`Access Request: ${vault?.name}`}
      variant="primary"
      size="medium"
      privacySensitive={true}
      footer={
        <div className="flex justify-end space-x-3">
          <button 
            type="button"
            className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md shadow-sm hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-blue-500"
            onClick={onClose}
          >
            Deny
          </button>
          <button 
            type="button"
            className="px-4 py-2 text-sm font-medium text-white bg-blue-600 border border-transparent rounded-md shadow-sm hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500"
            onClick={() => {
              onGrantAccess(vault?.id);
              onClose();
            }}
          >
            Grant Access
          </button>
        </div>
      }
      {...props}
    >
      <div className="space-y-4">
        <div className="bg-blue-50 dark:bg-blue-900/30 p-3 rounded-lg">
          <p className="text-sm text-blue-800 dark:text-blue-200">
            <span className="font-semibold">Privacy Notice:</span> Granting access will utilize zero-knowledge proofs to verify access permissions without revealing underlying data.
          </p>
        </div>
        
        <div className="space-y-2">
          <div className="flex justify-between">
            <p className="text-sm text-gray-500 dark:text-gray-400">Requestor:</p>
            <p className="text-sm font-medium text-gray-900 dark:text-white">{vault?.requestor}</p>
          </div>
          <div className="flex justify-between">
            <p className="text-sm text-gray-500 dark:text-gray-400">Purpose:</p>
            <p className="text-sm font-medium text-gray-900 dark:text-white">{vault?.purpose}</p>
          </div>
          <div className="flex justify-between">
            <p className="text-sm text-gray-500 dark:text-gray-400">Access Level:</p>
            <p className="text-sm font-medium text-gray-900 dark:text-white">{vault?.accessLevel}</p>
          </div>
          <div className="flex justify-between">
            <p className="text-sm text-gray-500 dark:text-gray-400">Duration:</p>
            <p className="text-sm font-medium text-gray-900 dark:text-white">{vault?.duration}</p>
          </div>
        </div>
        
        <div className="border-t dark:border-gray-700 pt-3">
          <h4 className="font-medium text-gray-900 dark:text-white mb-2">Privacy Preservation Methods:</h4>
          <ul className="space-y-1">
            <li className="flex items-center text-sm text-gray-700 dark:text-gray-300">
              <svg className="w-4 h-4 mr-1.5 text-green-500 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path>
              </svg>
              Differential Privacy: {vault?.privacyMethods?.differentialPrivacy ? 'Enabled' : 'Disabled'}
            </li>
            <li className="flex items-center text-sm text-gray-700 dark:text-gray-300">
              <svg className="w-4 h-4 mr-1.5 text-green-500 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path>
              </svg>
              Federated Learning: {vault?.privacyMethods?.federatedLearning ? 'Enabled' : 'Disabled'}
            </li>
            <li className="flex items-center text-sm text-gray-700 dark:text-gray-300">
              <svg className="w-4 h-4 mr-1.5 text-green-500 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path>
              </svg>
              Secure MPC: {vault?.privacyMethods?.secureMpc ? 'Enabled' : 'Disabled'}
            </li>
          </ul>
        </div>
      </div>
    </Modal>
  );
};

DataVaultAccessModal.propTypes = {
  isOpen: PropTypes.bool.isRequired,
  onClose: PropTypes.func.isRequired,
  vault: PropTypes.shape({
    id: PropTypes.string,
    name: PropTypes.string,
    requestor: PropTypes.string,
    purpose: PropTypes.string,
    accessLevel: PropTypes.string,
    duration: PropTypes.string,
    privacyMethods: PropTypes.shape({
      differentialPrivacy: PropTypes.bool,
      federatedLearning: PropTypes.bool,
      secureMpc: PropTypes.bool,
    }),
  }),
  onGrantAccess: PropTypes.func.isRequired,
};

// Initialize modal root if it doesn't exist
if (typeof document !== 'undefined' && !document.getElementById('modal-root')) {
  const modalRoot = document.createElement('div');
  modalRoot.setAttribute('id', 'modal-root');
  document.body.appendChild(modalRoot);
}

export default Modal;
