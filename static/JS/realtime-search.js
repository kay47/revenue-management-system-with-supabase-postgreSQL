// ============================================
// REAL-TIME SEARCH - Complete Implementation
// Save this as: static/js/realtime-search.js
// ============================================

/**
 * Universal Real-Time Search for all list pages
 * Features:
 * - Instant filtering as you type
 * - Debounced for performance
 * - Clear button
 * - Results count
 * - Empty state handling
 * - Highlight matches (optional)
 */

(function() {
    'use strict';
    
    // Debounce helper
    function debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            clearTimeout(timeout);
            timeout = setTimeout(() => func(...args), wait);
        };
    }
    
    // Highlight matching text
    function highlightText(text, searchTerm) {
        if (!searchTerm) return text;
        const regex = new RegExp(`(${searchTerm})`, 'gi');
        return text.replace(regex, '<mark style="background: #fef3c7; padding: 0 2px;">$1</mark>');
    }
    
    // Main search class
    class RealTimeSearch {
        constructor(config) {
            this.config = {
                searchInputSelector: 'input[name="search"]',
                tableBodySelector: 'table tbody',
                resultsInfoSelector: '.results-summary > div:first-child',
                clearButtonClass: 'clear-search-btn',
                debounceTime: 300,
                highlightMatches: false,
                ...config
            };
            
            this.init();
        }
        
        init() {
            this.searchInput = document.querySelector(this.config.searchInputSelector);
            this.tableBody = document.querySelector(this.config.tableBodySelector);
            this.resultsInfo = document.querySelector(this.config.resultsInfoSelector);
            
            if (!this.searchInput || !this.tableBody) {
                console.warn('Real-time search: Required elements not found');
                return;
            }
            
            // Get all data rows (excluding empty state)
            this.allRows = Array.from(
                this.tableBody.querySelectorAll('tr:not(.empty-state)')
            );
            
            // Create clear button if it doesn't exist
            this.setupClearButton();
            
            // Create/find empty state row
            this.setupEmptyState();
            
            // Setup event listeners
            this.setupEventListeners();
            
            // Initial filter if there's a value
            if (this.searchInput.value.trim()) {
                this.filterRows(this.searchInput.value);
                this.clearButton.style.display = 'inline-block';
            }
        }
        
        setupClearButton() {
            // Check if clear button exists
            this.clearButton = document.querySelector('.' + this.config.clearButtonClass);
            
            if (!this.clearButton) {
                // Create clear button
                this.clearButton = document.createElement('button');
                this.clearButton.type = 'button';
                this.clearButton.className = this.config.clearButtonClass;
                this.clearButton.title = 'Clear search';
                this.clearButton.innerHTML = '<i class="fas fa-times-circle"></i>';
                this.clearButton.style.cssText = `
                    position: absolute;
                    right: 140px;
                    top: 50%;
                    transform: translateY(-50%);
                    background: none;
                    border: none;
                    color: #6b7280;
                    cursor: pointer;
                    padding: 0.5rem;
                    display: none;
                    transition: color 0.3s;
                    z-index: 10;
                `;
                
                // Insert after search input
                const parent = this.searchInput.parentElement;
                if (parent) {
                    parent.style.position = 'relative';
                    parent.appendChild(this.clearButton);
                }
            }
        }
        
        setupEmptyState() {
            this.emptyStateRow = this.tableBody.querySelector('.empty-state');
            
            if (!this.emptyStateRow && this.allRows.length > 0) {
                // Create empty state row
                this.emptyStateRow = document.createElement('tr');
                this.emptyStateRow.className = 'empty-state';
                this.emptyStateRow.style.display = 'none';
                
                const colspan = this.allRows[0]?.querySelectorAll('td').length || 5;
                this.emptyStateRow.innerHTML = `
                    <td colspan="${colspan}">
                        <div class="empty-state" style="text-align: center; padding: 3rem; color: #999;">
                            <i class="fas fa-search" style="font-size: 3rem; display: block; margin-bottom: 1rem; color: #d1d5db;"></i>
                            <h3 style="color: #374151; margin-bottom: 0.5rem;">No Results Found</h3>
                            <p style="margin: 0;">Try adjusting your search</p>
                        </div>
                    </td>
                `;
                
                this.tableBody.appendChild(this.emptyStateRow);
            }
        }
        
        setupEventListeners() {
            // Search input
            this.searchInput.addEventListener('input', 
                debounce((e) => this.filterRows(e.target.value), this.config.debounceTime)
            );
            
            // Clear button
            if (this.clearButton) {
                this.clearButton.addEventListener('click', () => {
                    this.searchInput.value = '';
                    this.filterRows('');
                    this.searchInput.focus();
                });
                
                // Hover effect
                this.clearButton.addEventListener('mouseenter', function() {
                    this.style.color = '#dc2626';
                });
                this.clearButton.addEventListener('mouseleave', function() {
                    this.style.color = '#6b7280';
                });
            }
        }
        
        filterRows(searchTerm) {
            searchTerm = searchTerm.toLowerCase().trim();
            let visibleCount = 0;
            const totalCount = this.allRows.length;
            
            // Filter rows
            this.allRows.forEach(row => {
                const searchableText = this.config.getSearchableText(row).toLowerCase();
                
                if (!searchTerm || searchableText.includes(searchTerm)) {
                    row.style.display = '';
                    visibleCount++;
                    
                    // Optional: Highlight matches
                    if (this.config.highlightMatches && searchTerm) {
                        // Implementation depends on your needs
                    }
                } else {
                    row.style.display = 'none';
                }
            });
            
            // Update UI
            this.updateResultsCount(visibleCount, totalCount, searchTerm);
            this.toggleEmptyState(visibleCount === 0 && searchTerm);
            this.toggleClearButton(searchTerm);
        }
        
        updateResultsCount(visibleCount, totalCount, searchTerm) {
            if (!this.resultsInfo) return;
            
            if (searchTerm) {
                this.resultsInfo.innerHTML = `
                    <strong>Showing ${visibleCount} of ${totalCount} results</strong>
                    <span style="color: #666;"> | Searching for "${searchTerm}"</span>
                `;
            } else {
                this.resultsInfo.innerHTML = `<strong>Total: ${totalCount}</strong>`;
            }
        }
        
        toggleEmptyState(show) {
            if (this.emptyStateRow) {
                this.emptyStateRow.style.display = show ? '' : 'none';
            }
        }
        
        toggleClearButton(show) {
            if (this.clearButton) {
                this.clearButton.style.display = show ? 'inline-block' : 'none';
            }
        }
    }
    
    // ============================================
    // PAGE-SPECIFIC CONFIGURATIONS
    // ============================================
    
    // Properties Search
    window.initPropertiesSearch = function() {
        return new RealTimeSearch({
            getSearchableText: (row) => {
                const cells = row.querySelectorAll('td');
                return [
                    cells[0]?.textContent || '', // Account No
                    cells[1]?.textContent || '', // Owner Name
                    cells[2]?.textContent || '', // Electoral Area
                    cells[3]?.textContent || '', // Town
                    cells[4]?.textContent || ''  // Category
                ].join(' ');
            }
        });
    };
    
    // Businesses Search
    window.initBusinessesSearch = function() {
        return new RealTimeSearch({
            getSearchableText: (row) => {
                const cells = row.querySelectorAll('td');
                return [
                    cells[0]?.textContent || '', // Account No
                    cells[1]?.textContent || '', // Business Name
                    cells[2]?.textContent || '', // Owner
                    cells[3]?.textContent || '', // Location
                    cells[4]?.textContent || '', // Category 1
                    cells[5]?.textContent || '', // Category 2
                    cells[6]?.textContent || '', // Category 3
                    cells[7]?.textContent || '', // Category 4
                    cells[8]?.textContent || '', // Category 5
                    cells[9]?.textContent || ''  // Category 6
                ].join(' ');
            }
        });
    };
    
    // Products Search
    window.initProductsSearch = function() {
        return new RealTimeSearch({
            getSearchableText: (row) => {
                const cells = row.querySelectorAll('td');
                return [
                    cells[0]?.textContent || '', // ID
                    cells[1]?.textContent || '', // Product Name
                    cells[3]?.textContent || '', // Category 1
                    cells[4]?.textContent || '', // Category 2
                    cells[5]?.textContent || '', // Category 3
                    cells[6]?.textContent || '', // Category 4
                    cells[7]?.textContent || '', // Category 5
                    cells[8]?.textContent || ''  // Category 6
                ].join(' ');
            }
        });
    };
    
    // Auto-initialize based on page
    document.addEventListener('DOMContentLoaded', function() {
        const path = window.location.pathname;
        
        if (path.includes('/properties')) {
            window.initPropertiesSearch();
            console.log('✓ Properties real-time search active');
        } else if (path.includes('/businesses')) {
            window.initBusinessesSearch();
            console.log('✓ Businesses real-time search active');
        } else if (path.includes('/products')) {
            window.initProductsSearch();
            console.log('✓ Products real-time search active');
        }
    });
    
})();