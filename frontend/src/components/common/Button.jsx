/**
 * Button Component
 * 
 * A versatile and accessible button component for the PrivaSight platform.
 * Implements design system using Tailwind CSS utility classes.
 */

import React, { forwardRef } from 'react';
import PropTypes from 'prop-types';

// Icon imports (assuming these are available in the project)
import { ArrowRight, ExternalLink } from '../icons';

const Button = forwardRef(({
  // Content
  children,
  icon,
  iconPosition = 'left',
  trailingIcon,
  
  // Styling
  variant = 'primary',
  size = 'medium',
  fullWidth = false,
  rounded = false,
  elevated = false,
  
  // States
  isLoading = false,
  isDisabled = false,
  isActive = false,
  
  // Link props
  href,
  target,
  rel,
  
  // Accessibility
  ariaLabel,
  ariaExpanded,
  ariaControls,
  ariaDescribedBy,
  
  // Events
  onClick,
  onFocus,
  onBlur,
  
  // Additional props
  className = '',
  ...props
}, ref) => {
  
  // Base classes that apply to all buttons
  const baseClasses = [
    'inline-flex items-center justify-center gap-2',
    'transition-all duration-200 ease-in-out',
    'font-medium text-center focus:outline-none',
    'disabled:opacity-65 disabled:cursor-not-allowed',
    fullWidth ? 'w-full' : '',
    rounded ? 'rounded-full' : 'rounded',
    elevated ? 'shadow hover:shadow-md' : '',
    isActive ? 'font-semibold' : '',
  ];
  
  // Size-specific classes
  const sizeClasses = {
    small: 'h-8 px-3 text-sm',
    medium: 'h-10 px-4 text-base',
    large: 'h-12 px-5 text-lg',
  };
  
  // Variant-specific classes
  const variantClasses = {
    primary: 'bg-blue-600 text-white hover:bg-blue-700 active:bg-blue-800 focus:ring focus:ring-blue-300',
    secondary: 'bg-gray-200 text-gray-800 hover:bg-gray-300 active:bg-gray-400 focus:ring focus:ring-gray-300 dark:bg-gray-700 dark:text-gray-100',
    tertiary: 'bg-transparent text-blue-600 ring-1 ring-blue-600 hover:bg-blue-50 active:bg-blue-100 focus:ring focus:ring-blue-300',
    ghost: 'bg-transparent text-gray-800 hover:bg-gray-100 active:bg-gray-200 dark:text-gray-100 dark:hover:bg-gray-800',
    danger: 'bg-red-600 text-white hover:bg-red-700 active:bg-red-800 focus:ring focus:ring-red-300',
    success: 'bg-green-600 text-white hover:bg-green-700 active:bg-green-800 focus:ring focus:ring-green-300',
    warning: 'bg-yellow-500 text-gray-900 hover:bg-yellow-600 active:bg-yellow-700 focus:ring focus:ring-yellow-300',
    info: 'bg-cyan-600 text-white hover:bg-cyan-700 active:bg-cyan-800 focus:ring focus:ring-cyan-300',
    analytics: 'bg-purple-600 text-white hover:bg-purple-700 active:bg-purple-800 focus:ring focus:ring-purple-300',
  };
  
  // Handle automatic trailing icon for external links
  const shouldShowExternalIcon = href && target === '_blank' && !trailingIcon;
  const finalTrailingIcon = shouldShowExternalIcon ? <ExternalLink className="w-4 h-4" /> : trailingIcon;
  
  // Build final class name
  const classes = [
    ...baseClasses,
    sizeClasses[size],
    variantClasses[variant],
    className
  ].filter(Boolean).join(' ');
  
  // Render button content
  const renderContent = () => (
    <>
      {isLoading && (
        <svg className="animate-spin -ml-1 mr-2 h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
        </svg>
      )}
      
      {icon && iconPosition === 'left' && (
        <span className="btn-icon">{icon}</span>
      )}
      
      {children && (
        <span className={isLoading ? 'opacity-0' : ''}>{children}</span>
      )}
      
      {icon && iconPosition === 'right' && (
        <span className="btn-icon">{icon}</span>
      )}
      
      {finalTrailingIcon && (
        <span className="btn-icon">{finalTrailingIcon}</span>
      )}
    </>
  );

  // If href is provided, render an anchor tag
  if (href) {
    const anchorRelAttr = target === '_blank' ? rel || 'noopener noreferrer' : rel;
    
    return (
      <a
        ref={ref}
        href={isDisabled ? undefined : href}
        target={target}
        rel={anchorRelAttr}
        className={classes}
        aria-label={ariaLabel}
        aria-disabled={isDisabled}
        aria-describedby={ariaDescribedBy}
        onClick={isDisabled ? (e) => e.preventDefault() : onClick}
        onFocus={onFocus}
        onBlur={onBlur}
        tabIndex={isDisabled ? -1 : 0}
        {...props}
      >
        {renderContent()}
      </a>
    );
  }

  // Otherwise render a button element
  return (
    <button
      ref={ref}
      type={props.type || 'button'}
      className={classes}
      disabled={isDisabled || isLoading}
      aria-label={ariaLabel}
      aria-expanded={ariaExpanded}
      aria-controls={ariaControls}
      aria-busy={isLoading}
      aria-describedby={ariaDescribedBy}
      onClick={onClick}
      onFocus={onFocus}
      onBlur={onBlur}
      {...props}
    >
      {renderContent()}
    </button>
  );
});

// Display name for debugging
Button.displayName = 'Button';

Button.propTypes = {
  // Content
  children: PropTypes.node,
  icon: PropTypes.node,
  iconPosition: PropTypes.oneOf(['left', 'right']),
  trailingIcon: PropTypes.node,
  
  // Styling
  variant: PropTypes.oneOf([
    'primary',
    'secondary',
    'tertiary',
    'ghost',
    'danger',
    'success',
    'warning',
    'info',
    'analytics'
  ]),
  size: PropTypes.oneOf(['small', 'medium', 'large']),
  fullWidth: PropTypes.bool,
  rounded: PropTypes.bool,
  elevated: PropTypes.bool,
  
  // States
  isLoading: PropTypes.bool,
  isDisabled: PropTypes.bool,
  isActive: PropTypes.bool,
  
  // Link props
  href: PropTypes.string,
  target: PropTypes.string,
  rel: PropTypes.string,
  
  // Accessibility
  ariaLabel: PropTypes.string,
  ariaExpanded: PropTypes.bool,
  ariaControls: PropTypes.string,
  ariaDescribedBy: PropTypes.string,
  
  // Events
  onClick: PropTypes.func,
  onFocus: PropTypes.func,
  onBlur: PropTypes.func,
  
  // Additional props
  className: PropTypes.string,
  type: PropTypes.oneOf(['button', 'submit', 'reset'])
};

export default Button;

// Helper components for specialized buttons
export const ActionButton = (props) => (
  <Button
    variant="primary"
    trailingIcon={<ArrowRight className="w-4 h-4" />}
    {...props}
  />
);

export const IconButton = forwardRef(({ children, icon, ariaLabel, ...props }, ref) => (
  <Button
    ref={ref}
    icon={icon}
    ariaLabel={ariaLabel || (typeof children === 'string' ? children : undefined)}
    {...props}
  >
    {children}
  </Button>
));

IconButton.displayName = 'IconButton';

export const PrivacyButton = (props) => (
  <Button
    variant="analytics"
    {...props}
  />
);
