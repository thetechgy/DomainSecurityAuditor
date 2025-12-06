<#
.SYNOPSIS
    Provide client-side script for the HTML report.
.DESCRIPTION
    Returns JavaScript that powers expand/collapse controls, status filtering, and keyboard accessibility for the report UI.
#>
function Get-DSAReportScript {
    @"
const protocolSections = document.querySelectorAll('.protocol-section');
const toggleAllSectionsButton = document.getElementById('toggle-all-sections');

const isSectionVisible = (section) => {
    if (!section) {
        return false;
    }
    const domain = section.closest('.domain-results');
    const domainVisible = !domain || domain.style.display !== 'none';
    return domainVisible && section.style.display !== 'none';
};

const getVisibleSections = () => Array.from(protocolSections).filter((section) => isSectionVisible(section));

const setSectionExpanded = (section, header, details, expanded) => {
    section.classList.toggle('expanded', expanded);
    if (details) {
        details.classList.toggle('expanded', expanded);
        details.setAttribute('aria-hidden', expanded ? 'false' : 'true');
    }
    if (header) {
        header.setAttribute('aria-expanded', expanded ? 'true' : 'false');
    }
};

const updateToggleAllLabel = () => {
    if (!toggleAllSectionsButton) {
        return;
    }
    const visibleSections = getVisibleSections();
    const allExpanded = visibleSections.length > 0 && visibleSections.every((section) => section.classList.contains('expanded'));
    toggleAllSectionsButton.textContent = allExpanded ? 'Collapse all sections' : 'Expand all sections';
    toggleAllSectionsButton.setAttribute('aria-pressed', allExpanded ? 'true' : 'false');
};

const setAllSectionsExpanded = (expanded) => {
    protocolSections.forEach((section) => {
        if (!isSectionVisible(section)) {
            return;
        }
        const header = section.querySelector('.protocol-header');
        const details = section.querySelector('.protocol-details');
        if (!header || !details) {
            return;
        }
        setSectionExpanded(section, header, details, expanded);
        if (!expanded) {
            delete section.dataset.filterExpanded;
        }
    });
    updateToggleAllLabel();
};

protocolSections.forEach((section) => {
    const header = section.querySelector('.protocol-header');
    const details = section.querySelector('.protocol-details');
    if (!header || !details) {
        return;
    }
    setSectionExpanded(section, header, details, false);

    const toggleSection = () => {
        const expanded = !section.classList.contains('expanded');
        setSectionExpanded(section, header, details, expanded);
        updateToggleAllLabel();
    };

    header.addEventListener('click', toggleSection);
    header.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            toggleSection();
        }
    });
});

if (toggleAllSectionsButton) {
    toggleAllSectionsButton.addEventListener('click', () => {
        const visibleSections = getVisibleSections();
        const shouldExpand = visibleSections.some((section) => !section.classList.contains('expanded'));
        setAllSectionsExpanded(shouldExpand);
    });
}

const filterCards = document.querySelectorAll('.summary-cards .card[data-filter]');
const domainSections = document.querySelectorAll('.domain-results');
const filterSummary = document.getElementById('filter-summary');
let activeFilters = ['all'];

const setCardState = (card, isActive) => {
    card.classList.toggle('active', isActive);
    card.setAttribute('aria-pressed', isActive ? 'true' : 'false');
};

const renderFilterSummary = () => {
    if (!filterSummary) {
        return;
    }
    if (activeFilters.includes('all')) {
        filterSummary.textContent = 'Showing: All checks';
    } else {
        const pretty = activeFilters.map(f => {
            switch (f) {
                case 'pass': return 'Passing';
                case 'fail': return 'Failing';
                case 'warning': return 'Warning';
                default: return f;
            }
        });
        filterSummary.textContent = 'Showing: ' + pretty.join(', ');
    }
};

const applyDomainFilter = (filters) => {
    const normalizedFilters = (filters || ['all']).map(f => (f || 'all').toLowerCase());
    const matchAll = normalizedFilters.includes('all');

    domainSections.forEach(domain => {
        let domainHasMatch = false;
        const protocols = domain.querySelectorAll('.protocol-section');

        protocols.forEach(section => {
            const details = section.querySelector('.protocol-details');
            const tests = section.querySelectorAll('.test-result');
            let sectionHasMatch = false;

            tests.forEach(test => {
                const status = (test.getAttribute('data-status') || '').toLowerCase();
                const matches = matchAll || normalizedFilters.includes(status);
                test.style.display = matches ? '' : 'none';
                if (matches) {
                    sectionHasMatch = true;
                }
            });

            if (matchAll) {
                section.style.display = '';
                setSectionExpanded(section, section.querySelector('.protocol-header'), details, section.classList.contains('expanded'));
                delete section.dataset.filterExpanded;
            } else if (sectionHasMatch) {
                section.style.display = '';
                domainHasMatch = true;
                setSectionExpanded(section, section.querySelector('.protocol-header'), details, true);
                section.dataset.filterExpanded = 'true';
            } else {
                section.style.display = 'none';
                setSectionExpanded(section, section.querySelector('.protocol-header'), details, false);
                delete section.dataset.filterExpanded;
            }
        });

        domain.style.display = (matchAll || domainHasMatch) ? '' : 'none';
    });
    updateToggleAllLabel();
};

filterCards.forEach(card => {
    card.addEventListener('click', () => {
        const filter = card.getAttribute('data-filter') || 'all';
        if (filter === 'all') {
            activeFilters = ['all'];
            filterCards.forEach(c => setCardState(c, c.getAttribute('data-filter') === 'all'));
        } else {
            const isActive = card.classList.contains('active');
            if (isActive) {
                activeFilters = activeFilters.filter(f => f !== filter);
            } else {
                activeFilters = activeFilters.filter(f => f !== 'all');
                activeFilters.push(filter);
            }
            if (activeFilters.length === 0) {
                activeFilters = ['all'];
            }
            filterCards.forEach(c => {
                const f = c.getAttribute('data-filter');
                setCardState(c, activeFilters.includes(f));
            });
        }
        renderFilterSummary();
        applyDomainFilter(activeFilters);
    });

    card.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            card.click();
        }
    });
});

const defaultFilter = document.querySelector('.summary-cards .card[data-filter=\"all\"]');
if (defaultFilter) {
    activeFilters = ['all'];
    setCardState(defaultFilter, true);
    filterCards.forEach(c => {
        if (c !== defaultFilter) {
            setCardState(c, false);
        }
    });
    renderFilterSummary();
    applyDomainFilter(activeFilters);
} else {
    activeFilters = ['all'];
    renderFilterSummary();
    applyDomainFilter(activeFilters);
}
"@
}

