# PrivaSight Project File Structure

Below is the complete file structure for the PrivaSight platform, organized by component:

```
privasight/
│
├── .github/                          # GitHub configuration
│   ├── workflows/                    # CI/CD workflows
│   │   ├── build.yml                 # Build workflow
│   │   ├── test.yml                  # Test workflow
│   │   └── deploy.yml                # Deployment workflow
│   └── ISSUE_TEMPLATE/               # Issue templates
│
├── assets/                           # Static assets
│   ├── images/                       # Image files
│   │   ├── privasight-banner.png     # Project banner
│   │   ├── logo.svg                  # Project logo
│   │   └── icons/                    # UI icons
│   └── docs/                         # Documentation assets
│
├── contracts/                        # Smart contracts
│   ├── core/                         # Core contracts
│   │   ├── DataVaultNFT.sol          # DataVault NFT implementation
│   │   ├── PrivaToken.sol            # PRIVA token contract
│   │   └── Governance.sol            # Governance contract
│   ├── marketplace/                  # Marketplace contracts
│   │   ├── DataMarketplace.sol       # Data marketplace implementation
│   │   ├── AccessControl.sol         # Access control logic
│   │   └── RevenueShare.sol          # Revenue distribution logic
│   ├── privacy/                      # Privacy-related contracts
│   │   ├── VerifierRegistry.sol      # ZKP verifier registry
│   │   ├── ResultPublisher.sol       # Secure computation result publisher
│   │   └── ProofValidator.sol        # Proof validation logic
│   ├── interfaces/                   # Contract interfaces
│   │   ├── IDataVaultNFT.sol         # DataVault interface
│   │   ├── IPrivaToken.sol           # Token interface
│   │   └── IMarketplace.sol          # Marketplace interface
│   └── test/                         # Contract test files
│       ├── DataVaultNFT.test.js      # Tests for DataVault NFT
│       ├── PrivaToken.test.js        # Tests for PRIVA token
│       └── Marketplace.test.js       # Tests for marketplace
│
├── privacy-layer/                    # Privacy infrastructure
│   ├── core/                         # Core privacy components
│   │   ├── index.js                  # Main entry point
│   │   ├── PrivacyLayer.js           # Privacy layer integration
│   │   ├── ZKPAccessVerifier.js      # ZKP verification implementation
│   │   └── SMPCOrchestrator.js       # SMPC coordination logic
│   ├── zkp/                          # Zero-knowledge proof components
│   │   ├── circuits/                 # ZKP circuit definitions
│   │   │   ├── access.circom         # Access control circuit
│   │   │   └── computation.circom    # Computation verification circuit
│   │   ├── proofs/                   # Proof generation and verification
│   │   │   ├── prover.js             # Proof generation
│   │   │   └── verifier.js           # Proof verification
│   │   └── utils/                    # ZKP utilities
│   │       ├── hash.js               # ZK-friendly hash functions
│   │       └── merkle.js             # Merkle tree implementation
│   ├── smpc/                         # Secure multi-party computation
│   │   ├── protocols/                # SMPC protocols
│   │   │   ├── average.js            # Protocol for computing averages
│   │   │   └── statistical.js        # Protocol for statistical analysis
│   │   ├── node.js                   # SMPC node implementation
│   │   ├── secret-sharing.js         # Secret sharing implementation
│   │   └── coordinator.js            # Computation coordination
│   ├── analytics/                    # Privacy-preserving analytics
│   │   ├── models/                   # Analytical models
│   │   │   ├── regression.js         # Privacy-preserving regression
│   │   │   └── clustering.js         # Privacy-preserving clustering
│   │   ├── federated-learning.js     # Federated learning implementation
│   │   └── differential-privacy.js   # Differential privacy utilities
│   └── test/                         # Privacy layer tests
│       ├── integration/              # Integration tests
│       │   ├── e2e.test.js           # End-to-end tests
│       │   └── privacy-flow.test.js  # Privacy workflow tests
│       ├── unit/                     # Unit tests
│       │   ├── zkp.test.js           # ZKP component tests
│       │   ├── smpc.test.js          # SMPC component tests
│       │   └── privacy-layer.test.js # Privacy layer tests
│       └── test-data/                # Test data
│           ├── vault-data.json       # Sample vault data
│           └── access-rules.json     # Sample access rules
│
├── frontend/                         # Frontend application
│   ├── public/                       # Public assets
│   │   ├── index.html                # HTML entry point
│   │   ├── favicon.ico               # Favicon
│   │   └── manifest.json             # PWA manifest
│   ├── src/                          # Source code
│   │   ├── components/               # UI components
│   │   │   ├── common/               # Common UI components
│   │   │   │   ├── Button.jsx        # Button component
│   │   │   │   ├── Card.jsx          # Card component
│   │   │   │   └── Modal.jsx         # Modal component
│   │   │   ├── data-owner/           # Data owner UI components
│   │   │   │   ├── DataUpload.jsx    # Data upload component
│   │   │   │   ├── VaultManagement.jsx # Vault management UI
│   │   │   │   └── AccessControl.jsx # Access control settings
│   │   │   ├── researcher/           # Researcher UI components
│   │   │   │   ├── DataDiscovery.jsx # Data discovery interface
│   │   │   │   ├── AccessRequest.jsx # Access request UI
│   │   │   │   └── Results.jsx       # Results visualization
│   │   │   └── marketplace/          # Marketplace UI components
│   │   │       ├── Listings.jsx      # Data listings component
│   │   │       ├── Trading.jsx       # Trading interface
│   │   │       └── Analytics.jsx     # Marketplace analytics
│   │   ├── contexts/                 # React contexts
│   │   │   ├── WalletContext.jsx     # Wallet connection context
│   │   │   ├── DataContext.jsx       # Data management context
│   │   │   └── PrivacyContext.jsx    # Privacy settings context
│   │   ├── hooks/                    # Custom React hooks
│   │   │   ├── useDataVault.js       # DataVault interaction hook
│   │   │   ├── usePrivaToken.js      # PRIVA token interaction hook
│   │   │   └── usePrivacyLayer.js    # Privacy layer interaction hook
│   │   ├── pages/                    # Application pages
│   │   │   ├── Home.jsx              # Home page
│   │   │   ├── Dashboard.jsx         # User dashboard
│   │   │   ├── DataVaults.jsx        # DataVaults management
│   │   │   ├── Marketplace.jsx       # Marketplace page
│   │   │   ├── Research.jsx          # Research interface
│   │   │   └── Governance.jsx        # Governance page
│   │   ├── services/                 # Frontend services
│   │   │   ├── api.js                # API service
│   │   │   ├── web3.js               # Web3 integration
│   │   │   ├── encryption.js         # Client-side encryption
│   │   │   └── analytics.js          # Analytics service
│   │   ├── utils/                    # Utility functions
│   │   │   ├── formatting.js         # Data formatting utilities
│   │   │   ├── validation.js         # Input validation
│   │   │   └── privacy.js            # Privacy utilities
│   │   ├── App.jsx                   # Main application component
│   │   ├── index.jsx                 # Application entry point
│   │   └── routes.jsx                # Application routes
│   ├── tests/                        # Frontend tests
│   │   ├── components/               # Component tests
│   │   ├── pages/                    # Page tests
│   │   └── integration/              # Frontend integration tests
│   ├── package.json                  # Frontend dependencies
│   └── tailwind.config.js            # Tailwind CSS configuration
│
├── backend/                          # Backend services
│   ├── api/                          # API server
│   │   ├── routes/                   # API routes
│   │   │   ├── data.routes.js        # Data management routes
│   │   │   ├── user.routes.js        # User management routes
│   │   │   └── research.routes.js    # Research and analytics routes
│   │   ├── controllers/              # API controllers
│   │   │   ├── data.controller.js    # Data management logic
│   │   │   ├── user.controller.js    # User management logic
│   │   │   └── research.controller.js # Research management logic
│   │   ├── middleware/               # API middleware
│   │   │   ├── auth.js               # Authentication middleware
│   │   │   └── validation.js         # Input validation middleware
│   │   ├── models/                   # Data models
│   │   │   ├── user.model.js         # User model
│   │   │   ├── vault.model.js        # DataVault model
│   │   │   └── request.model.js      # Access request model
│   │   ├── services/                 # Backend services
│   │   │   ├── blockchain.service.js # Blockchain integration
│   │   │   ├── ipfs.service.js       # IPFS integration
│   │   │   └── analytics.service.js  # Analytics service
│   │   ├── utils/                    # Utility functions
│   │   │   ├── encryption.js         # Server-side encryption utilities
│   │   │   └── validation.js         # Input validation utilities
│   │   ├── app.js                    # Express application
│   │   └── server.js                 # Server entry point
│   ├── computation-nodes/            # SMPC computation nodes
│   │   ├── node-service.js           # Node service implementation
│   │   ├── computation.js            # Computation logic
│   │   └── network.js                # Node networking
│   ├── blockchain-indexer/           # Blockchain event indexer
│   │   ├── indexer.js                # Indexing service
│   │   ├── processors/               # Event processors
│   │   │   ├── vault-processor.js    # DataVault event processor
│   │   │   └── market-processor.js   # Marketplace event processor
│   │   └── db/                       # Database integration
│   └── tests/                        # Backend tests
│       ├── api/                      # API tests
│       ├── computation/              # Computation node tests
│       └── indexer/                  # Indexer tests
│
├── docs/                             # Documentation
│   ├── api/                          # API documentation
│   ├── architecture/                 # Architecture documentation
│   │   ├── overview.md               # Architecture overview
│   │   ├── privacy-layer.md          # Privacy layer details
│   │   └── smart-contracts.md        # Smart contract documentation
│   ├── guides/                       # User guides
│   │   ├── data-owners.md            # Guide for data owners
│   │   ├── researchers.md            # Guide for researchers
│   │   └── developers.md             # Guide for developers
│   ├── privacy/                      # Privacy documentation
│   │   ├── zkp.md                    # ZKP documentation
│   │   ├── smpc.md                   # SMPC documentation
│   │   └── privacy-guarantees.md     # Privacy guarantees explanation
│   └── tokenomics/                   # Token economy documentation
│       ├── priva-token.md            # PRIVA token documentation
│       └── reward-model.md           # Reward model documentation
│
├── scripts/                          # Development scripts
│   ├── setup.sh                      # Environment setup script
│   ├── deploy.js                     # Contract deployment script
│   ├── generate-test-data.js         # Test data generation script
│   └── analyze-contracts.js          # Contract analysis script
│
├── .env.example                      # Example environment variables
├── .gitignore                        # Git ignore file
├── .eslintrc.js                      # ESLint configuration
├── .prettierrc                       # Prettier configuration
├── jest.config.js                    # Jest configuration
├── hardhat.config.js                 # Hardhat configuration
├── tsconfig.json                     # TypeScript configuration
├── package.json                      # Project dependencies
├── LICENSE                           # License file
├── CONTRIBUTING.md                   # Contributing guidelines
└── README.md                         # Project README
```

## Component Descriptions

### Smart Contracts (`/contracts`)

The smart contract layer implements the on-chain components of PrivaSight:

- **DataVaultNFT.sol**: Core NFT implementation for data vaults, including minting, access control, and usage tracking
- **PrivaToken.sol**: ERC-20 token with staking and governance functionality
- **Marketplace**: Contracts for listing, trading, and managing data access

### Privacy Layer (`/privacy-layer`)

The privacy infrastructure implements the core privacy-preserving mechanisms:

- **ZKP Components**: Zero-Knowledge Proof circuits and verification for access control
- **SMPC Implementation**: Secure Multi-Party Computation for private data analysis
- **Analytics Modules**: Privacy-preserving algorithms for generating insights

### Frontend (`/frontend`)

User interface for data owners, researchers, and platform participants:

- **Data Owner UI**: Tools for uploading data, minting vaults, and managing access
- **Researcher UI**: Interface for discovering data, requesting access, and viewing results
- **Marketplace**: Interface for trading data access rights

### Backend (`/backend`)

Supporting services for platform operation:

- **API Server**: RESTful API for application functionality
- **Computation Nodes**: Infrastructure for SMPC computation
- **Blockchain Indexer**: Service for processing and indexing blockchain events

### Documentation (`/docs`)

Comprehensive documentation for all aspects of the platform:

- **API Documentation**: Reference for the API endpoints
- **Architecture Documentation**: Technical details of system design
- **User Guides**: Instructions for different user roles
- **Privacy Documentation**: Technical explanation of privacy guarantees

## Design Patterns

### Smart Contracts

- **ERC-721 for DataVault NFTs**: Represents data ownership as non-fungible tokens
- **Access Control Pattern**: Granular permissions for data access
- **Proxy Pattern**: Upgradeable contracts for future improvements
- **Event-driven Architecture**: Emits events for off-chain indexing and notifications

### Privacy Layer

- **ZKP Circuit Design**: Custom circuits for access verification and computation proof
- **Secret Sharing**: Shamir's Secret Sharing for distributing data across nodes
- **Secure Aggregation**: Protocol for combining results without exposing individual data
- **Threshold Encryption**: Requires multiple parties to cooperate for decryption

### Frontend

- **Component-based Architecture**: Reusable UI components
- **Context API for State Management**: Manages application state
- **Custom Hooks for Blockchain Interaction**: Abstracts Web3 integration
- **Responsive Design**: Mobile-first approach with Tailwind CSS

### Backend

- **Microservices Architecture**: Separated concerns with dedicated services
- **Event-Sourcing Pattern**: Records all state changes as events
- **CQRS Pattern**: Separates read and write operations
- **Middleware Pipeline**: Extensible request processing
