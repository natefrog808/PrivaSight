/**
 * Card Component
 * 
 * A versatile card component for displaying content in the PrivaSight platform.
 * Supports various styles, hover effects, content layouts, and specialized variants.
 */

import React, { forwardRef } from 'react';
import PropTypes from 'prop-types';

// Base Card Component
const Card = forwardRef(({
  // Content props
  children,
  title,
  subtitle,
  header,
  footer,
  headerClassName,
  footerClassName,
  bodyClassName,

  // Styling props
  variant = 'default',
  padding = 'medium',
  elevated = false,
  hoverable = false,
  bordered = true,
  fullWidth = false,
  rounded = true,

  // State props
  isActive = false,
  isDisabled = false,
  isLoading = false,

  // Interactive props
  onClick,
  href,

  // Additional props
  className = '',
  ...props
}, ref) => {

  // Base classes for consistent styling
  const baseClasses = [
    'bg-white dark:bg-gray-800',
    'transition-all duration-200',
    rounded ? 'rounded-lg' : '',
    bordered ? 'border border-gray-200 dark:border-gray-700' : '',
    elevated ? 'shadow-md' : 'shadow-sm',
    hoverable ? 'hover:shadow-lg hover:-translate-y-1' : '',
    isActive ? 'ring-2 ring-blue-500 dark:ring-blue-400' : '',
    isDisabled ? 'opacity-60 pointer-events-none' : '',
    fullWidth ? 'w-full' : '',
    isLoading ? 'animate-pulse' : '',
    onClick || href ? 'cursor-pointer' : '',
  ];

  // Variant-specific styling
  const variantClasses = {
    default: '',
    primary: 'border-l-4 border-l-blue-500',
    secondary: 'border-l-4 border-l-gray-500',
    success: 'border-l-4 border-l-green-500',
    danger: 'border-l-4 border-l-red-500',
    warning: 'border-l-4 border-l-yellow-500',
    info: 'border-l-4 border-l-cyan-500',
    analytics: 'border-l-4 border-l-purple-500',
  };

  // Padding options
  const paddingClasses = {
    none: '',
    small: 'p-2',
    medium: 'p-4',
    large: 'p-6',
  };

  // Combine all classes for the card container
  const cardClasses = [
    ...baseClasses,
    variantClasses[variant] || variantClasses.default,
    className,
  ].filter(Boolean).join(' ');

  // Default header when title is provided
  const defaultHeader = title && (
    <div className={`mb-2 ${headerClassName || ''}`}>
      {title && <h3 className="text-lg font-semibold text-gray-900 dark:text-white">{title}</h3>}
      {subtitle && <p className="text-sm text-gray-600 dark:text-gray-400">{subtitle}</p>}
    </div>
  );

  // Card content with loading state
  const content = (
    <>
      {header || defaultHeader}
      <div className={bodyClassName || ''}>
        {isLoading ? (
          <div className="space-y-2">
            <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded"></div>
            <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-5/6"></div>
            <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-4/6"></div>
          </div>
        ) : (
          children
        )}
      </div>
      {footer && (
        <div className={`mt-3 ${footerClassName || ''}`}>
          {footer}
        </div>
      )}
    </>
  );

  // Render as a link if href is provided
  if (href) {
    return (
      <a
        ref={ref}
        href={href}
        className={cardClasses}
        {...props}
      >
        <div className={paddingClasses[padding]}>
          {content}
        </div>
      </a>
    );
  }

  // Render as a clickable element if onClick is provided
  if (onClick) {
    return (
      <div
        ref={ref}
        role="button"
        tabIndex={0}
        className={cardClasses}
        onClick={onClick}
        onKeyDown={(e) => e.key === 'Enter' && onClick(e)}
        {...props}
      >
        <div className={paddingClasses[padding]}>
          {content}
        </div>
      </div>
    );
  }

  // Default render as a static div
  return (
    <div
      ref={ref}
      className={cardClasses}
      {...props}
    >
      <div className={paddingClasses[padding]}>
        {content}
      </div>
    </div>
  );
});

Card.displayName = 'Card';

// PropTypes for type checking and documentation
Card.propTypes = {
  // Content
  children: PropTypes.node,
  title: PropTypes.node,
  subtitle: PropTypes.node,
  header: PropTypes.node,
  footer: PropTypes.node,
  headerClassName: PropTypes.string,
  footerClassName: PropTypes.string,
  bodyClassName: PropTypes.string,

  // Styling
  variant: PropTypes.oneOf([
    'default',
    'primary',
    'secondary',
    'success',
    'danger',
    'warning',
    'info',
    'analytics',
  ]),
  padding: PropTypes.oneOf(['none', 'small', 'medium', 'large']),
  elevated: PropTypes.bool,
  hoverable: PropTypes.bool,
  bordered: PropTypes.bool,
  fullWidth: PropTypes.bool,
  rounded: PropTypes.bool,

  // States
  isActive: PropTypes.bool,
  isDisabled: PropTypes.bool,
  isLoading: PropTypes.bool,

  // Interactive props
  onClick: PropTypes.func,
  href: PropTypes.string,

  // Additional props
  className: PropTypes.string,
};

// Specialized Card Variants

/** DataVaultCard: Displays record count and last updated info */
export const DataVaultCard = ({ totalRecords, lastUpdated, ...props }) => (
  <Card
    variant="primary"
    hoverable
    footer={
      <div className="flex justify-between text-xs text-gray-500 dark:text-gray-400">
        <span>{totalRecords && `${totalRecords.toLocaleString()} records`}</span>
        <span>{lastUpdated && `Updated: ${lastUpdated}`}</span>
      </div>
    }
    {...props}
  />
);

DataVaultCard.propTypes = {
  totalRecords: PropTypes.number,
  lastUpdated: PropTypes.string,
};

/** AnalyticsCard: Displays a metric with value and optional delta */
export const AnalyticsCard = ({ metric, value, delta, ...props }) => {
  const isPositive = delta > 0;
  const isNegative = delta < 0;

  return (
    <Card
      variant="analytics"
      elevated
      {...props}
    >
      <div className="flex flex-col">
        <span className="text-sm font-medium text-gray-500 dark:text-gray-400">{metric}</span>
        <span className="text-2xl font-bold text-gray-900 dark:text-white">{value}</span>
        {delta != null && (
          <span className={`text-xs font-medium mt-1 flex items-center
            ${isPositive ? 'text-green-600 dark:text-green-400' : ''}
            ${isNegative ? 'text-red-600 dark:text-red-400' : ''}
            ${!isPositive && !isNegative ? 'text-gray-500 dark:text-gray-400' : ''}`}>
            {isPositive && <span className="mr-1">↑</span>}
            {isNegative && <span className="mr-1">↓</span>}
            {delta !== 0 ? `${Math.abs(delta).toFixed(1)}%` : 'No change'}
          </span>
        )}
      </div>
    </Card>
  );
};

AnalyticsCard.propTypes = {
  metric: PropTypes.string.isRequired,
  value: PropTypes.oneOfType([PropTypes.string, PropTypes.number]).isRequired,
  delta: PropTypes.number,
};

/** PrivacySettingCard: Displays a setting with a toggle switch */
export const PrivacySettingCard = ({ title, description, enabled, onChange, ...props }) => (
  <Card
    variant={enabled ? 'success' : 'default'}
    {...props}
  >
    <div className="flex items-start justify-between">
      <div>
        <h4 className="font-medium text-gray-900 dark:text-white">{title}</h4>
        <p className="text-sm text-gray-500 dark:text-gray-400">{description}</p>
      </div>
      <label className="relative inline-flex items-center cursor-pointer">
        <input
          type="checkbox"
          className="sr-only peer"
          checked={enabled}
          onChange={onChange}
        />
        <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-blue-600"></div>
      </label>
    </div>
  </Card>
);

PrivacySettingCard.propTypes = {
  title: PropTypes.string.isRequired,
  description: PropTypes.string,
  enabled: PropTypes.bool.isRequired,
  onChange: PropTypes.func.isRequired,
};

// Export the components
export default Card;
