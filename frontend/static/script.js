// Global variables
let cameraStream = null;
let isScanning = false;
let scanInterval = null;
let lastScanTime = 0;
let scannedHistory = []; // Store all scanned results
let lastScannedResult = null; // Store the most recent scan result
const SCAN_DEBOUNCE_MS = 2000; // Only scan every 2 seconds

// DOM elements
const startCameraBtn = document.getElementById('start-camera');
const stopCameraBtn = document.getElementById('stop-camera');
const refreshResultsBtn = document.getElementById('refresh-results');
const testConnectionBtn = document.getElementById('test-connection');
const camera = document.getElementById('camera');
const canvas = document.getElementById('canvas');
const latestResultsContainer = document.getElementById('latest-results');
const historyResultsContainer = document.getElementById('history-results');
const urlInput = document.getElementById('url-input');
const analyzeBtn = document.getElementById('analyze-btn');
const loadingOverlay = document.getElementById('loading-overlay');
const tabBtns = document.querySelectorAll('.tab-btn');
const scanningFrame = document.querySelector('.scanning-frame');
const scanningLine = document.querySelector('.scanning-line');

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM loaded, initializing...');
    initializeEventListeners();
    initializeTabs();
    initializeImageUpload();
    console.log('Initialization complete');
});

// Event Listeners
function initializeEventListeners() {
    startCameraBtn.addEventListener('click', startCamera);
    stopCameraBtn.addEventListener('click', stopCamera);
    refreshResultsBtn.addEventListener('click', refreshResults);
    testConnectionBtn.addEventListener('click', testConnection);
    analyzeBtn.addEventListener('click', analyzeUrl);
    urlInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            analyzeUrl();
        }
    });
    
    // Tab functionality
    document.querySelectorAll('.tab-button').forEach(button => {
        button.addEventListener('click', function() {
            const tabName = this.getAttribute('data-tab');
            switchTab(tabName);
        });
    });
    
    // Mode tab functionality (camera/image)
    const modeTabs = document.querySelectorAll('.tab-btn');
    console.log('Found mode tabs:', modeTabs.length);
    modeTabs.forEach(button => {
        console.log('Adding event listener to tab:', button.getAttribute('data-mode'));
        button.addEventListener('click', function() {
            const mode = this.getAttribute('data-mode');
            console.log('Mode tab clicked:', mode);
            switchMode(mode);
        });
    });
}

// Tab functionality
function initializeTabs() {
    // Results tab functionality
    document.querySelectorAll('.tab-button').forEach(button => {
        button.addEventListener('click', function() {
            const tabName = this.getAttribute('data-tab');
            switchResultsTab(tabName);
        });
    });
}

function switchResultsTab(tabName) {
    // Remove active class from all tabs and panes
    document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(pane => pane.classList.remove('active'));
    
    // Add active class to selected tab and pane
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
    document.getElementById(`${tabName}-tab`).classList.add('active');
    
    // Handle special tab actions
    if (tabName === 'clear') {
        clearAllResults();
        // Switch back to latest tab after clearing
        setTimeout(() => switchResultsTab('latest'), 100);
    }
}

// Mode switching function (camera/image)
function switchMode(mode) {
    console.log('Switching to mode:', mode);
    
    // Update active mode tab
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
        if (btn.getAttribute('data-mode') === mode) {
            btn.classList.add('active');
        }
    });
    
    // Show/hide panels using IDs
    const cameraPanel = document.getElementById('camera-panel');
    const imagePanel = document.getElementById('image-panel');
    
    console.log('Camera panel found:', !!cameraPanel);
    console.log('Image panel found:', !!imagePanel);
    
    if (mode === 'camera') {
        console.log('Showing camera panel, hiding image panel');
        if (cameraPanel) {
            cameraPanel.style.display = 'block';
            cameraPanel.classList.add('active');
        }
        if (imagePanel) {
            imagePanel.style.display = 'none';
            imagePanel.classList.remove('active');
        }
    } else if (mode === 'image') {
        console.log('Showing image panel, hiding camera panel');
        if (cameraPanel) {
            cameraPanel.style.display = 'none';
            cameraPanel.classList.remove('active');
        }
        if (imagePanel) {
            imagePanel.style.display = 'block';
            imagePanel.classList.add('active');
        }
    }
}

// Camera functionality
async function startCamera() {
    try {
        cameraStream = await navigator.mediaDevices.getUserMedia({
            video: {
                facingMode: 'environment', // Use back camera on mobile
                width: { ideal: 1280 },
                height: { ideal: 720 }
            }
        });
        
        camera.srcObject = cameraStream;
        camera.play();
        
        // Hide start button and show stop button
        startCameraBtn.classList.add('hidden');
        stopCameraBtn.classList.add('active');
        
        // Show scanning frame and line
        scanningFrame.classList.add('active');
        scanningLine.classList.add('active');
        
        isScanning = true;
        startScanning();
        
        showMessage('Camera started! Point at a QR code to scan.', 'success');
        
    } catch (error) {
        console.error('Error accessing camera:', error);
        showMessage('Unable to access camera. Please check permissions.', 'error');
    }
}

function stopCamera() {
    if (cameraStream) {
        cameraStream.getTracks().forEach(track => track.stop());
        cameraStream = null;
    }
    
    camera.srcObject = null;
    
    // Show start button and hide stop button
    startCameraBtn.classList.remove('hidden');
    stopCameraBtn.classList.remove('active');
    
    // Hide scanning frame and line
    scanningFrame.classList.remove('active');
    scanningLine.classList.remove('active');
    
    isScanning = false;
    stopScanning();
    
    showMessage('Camera stopped.', 'info');
}

// Test connection function
async function testConnection() {
    console.log('Testing connection to Flask backend...');
    try {
        const response = await fetch('/test_connection');
        const result = await response.json();
        console.log('Connection test result:', result);
        
        if (result.success) {
            showMessage('✅ Backend connection successful!', 'success');
        } else {
            showMessage('❌ Backend connection failed!', 'error');
        }
    } catch (error) {
        console.error('Connection test failed:', error);
        showMessage('❌ Backend connection failed: ' + error.message, 'error');
    }
}

// Refresh results function
function refreshResults() {
    console.log('Refreshing results...');
    if (lastScannedResult) {
        console.log('Displaying last scanned result:', lastScannedResult);
        displayResults([lastScannedResult]);
        showMessage('Results refreshed!', 'success');
    } else {
        console.log('No recent scan results to display');
        showMessage('No recent scan results found', 'info');
    }
}

function clearAllResults() {
    scannedHistory = [];
    lastScannedResult = null;
    updateLatestResults();
    updateHistoryResults();
    showMessage('All scan results cleared!', 'info');
}

// Image Upload Functionality
function initializeImageUpload() {
    const imageInput = document.getElementById('image-input');
    const uploadArea = document.getElementById('upload-area');
    const imagePreview = document.getElementById('image-preview');
    const previewImg = document.getElementById('preview-img');
    const removeImageBtn = document.getElementById('remove-image');
    const scanImageBtn = document.getElementById('scan-image-btn');

    // File input change
    imageInput.addEventListener('change', handleFileSelect);

    // Drag and drop functionality
    uploadArea.addEventListener('dragover', handleDragOver);
    uploadArea.addEventListener('dragleave', handleDragLeave);
    uploadArea.addEventListener('drop', handleDrop);

    // Click to upload
    uploadArea.addEventListener('click', () => {
        imageInput.click();
    });

    // Remove image
    removeImageBtn.addEventListener('click', removeImage);

    // Scan image
    scanImageBtn.addEventListener('click', scanUploadedImage);

    function handleFileSelect(event) {
        const file = event.target.files[0];
        if (file && file.type.startsWith('image/')) {
            displayImagePreview(file);
        } else {
            showMessage('Please select a valid image file', 'error');
        }
    }

    function handleDragOver(event) {
        event.preventDefault();
        uploadArea.classList.add('dragover');
    }

    function handleDragLeave(event) {
        event.preventDefault();
        uploadArea.classList.remove('dragover');
    }

    function handleDrop(event) {
        event.preventDefault();
        uploadArea.classList.remove('dragover');
        
        const files = event.dataTransfer.files;
        if (files.length > 0) {
            const file = files[0];
            if (file.type.startsWith('image/')) {
                displayImagePreview(file);
            } else {
                showMessage('Please drop a valid image file', 'error');
            }
        }
    }

    function displayImagePreview(file) {
        const reader = new FileReader();
        reader.onload = function(e) {
            previewImg.src = e.target.result;
            uploadArea.style.display = 'none';
            imagePreview.style.display = 'block';
            showMessage('Image uploaded successfully!', 'success');
        };
        reader.readAsDataURL(file);
    }

    function removeImage() {
        uploadArea.style.display = 'block';
        imagePreview.style.display = 'none';
        imageInput.value = '';
        previewImg.src = '';
        showMessage('Image removed', 'info');
    }

    async function scanUploadedImage() {
        if (!previewImg.src) {
            showMessage('Please upload an image first', 'error');
            return;
        }

        showLoading(true);
        showMessage('Scanning image for QR codes...', 'info');

        try {
            // Convert image to base64
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            canvas.width = previewImg.naturalWidth;
            canvas.height = previewImg.naturalHeight;
            ctx.drawImage(previewImg, 0, 0);
            const imageData = canvas.toDataURL('image/jpeg', 0.8);

            // Send to server for QR detection
            const response = await fetch('/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ image: imageData })
            });

            const result = await response.json();
            console.log('Image scan result:', result);

            if (result.success && result.results && result.results.length > 0) {
                console.log('QR codes found in image:', result.results.length);
                result.results.forEach(qrResult => {
                    showScanNotification(qrResult);
                });
                displayResults(result.results);
                showMessage(`Found ${result.results.length} QR code(s) in image!`, 'success');
            } else {
                console.log('No QR codes found in image');
                showMessage('No QR codes found in the uploaded image', 'info');
            }

        } catch (error) {
            console.error('Error scanning image:', error);
            showMessage('Error scanning image: ' + error.message, 'error');
        } finally {
            showLoading(false);
        }
    }
}


function startScanning() {
    scanInterval = setInterval(captureAndScan, 2000); // Scan every 2 seconds
}

function stopScanning() {
    if (scanInterval) {
        clearInterval(scanInterval);
        scanInterval = null;
    }
}

async function captureAndScan() {
    if (!isScanning || !camera.videoWidth) return;
    
    // Debounce scanning to avoid overwhelming the system
    const now = Date.now();
    if (now - lastScanTime < SCAN_DEBOUNCE_MS) {
        return;
    }
    lastScanTime = now;
    
    try {
        // Capture frame from video
        const context = canvas.getContext('2d');
        canvas.width = camera.videoWidth;
        canvas.height = camera.videoHeight;
        context.drawImage(camera, 0, 0);
        
        console.log('Captured frame, attempting QR detection...');
        
        // Add visual feedback
        showMessage('Scanning for QR codes...', 'info');
        console.log('Starting QR detection process...');
        
        // Try client-side QR detection first (more reliable)
        const imageData = canvas.toDataURL('image/png');
        console.log('Image data length:', imageData.length);
        
        try {
            const qrResult = await QrScanner.scanImage(imageData);
            
            if (qrResult) {
                console.log('QR Code detected via client-side:', qrResult);
                
                // Show success message
                showMessage(`✅ Successfully scanned: ${qrResult}`, 'success');
                
                // Send URL to backend for analysis
                const response = await fetch('/analyze_url', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ url: qrResult })
                });
                
                const result = await response.json();
                console.log('Client-side analysis result:', result);
                
                if (result.success) {
                    console.log('Displaying client-side results...');
                    lastScannedResult = result; // Store the result
                    displayResults([result]);
                    showScanNotification(result);
                } else {
                    console.error('Client-side analysis failed:', result.error);
                }
                return; // Exit early if client-side worked
            }
        } catch (clientError) {
            console.log('Client-side QR detection failed:', clientError);
        }
        
        // If client-side detection fails, try server-side
        console.log('Trying server-side detection...');
        const imageDataJpeg = canvas.toDataURL('image/jpeg', 0.8);
        
        const response = await fetch('/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ image: imageDataJpeg })
        });
        
        const result = await response.json();
        console.log('Server response:', result);
        
        if (result.success && result.results && result.results.length > 0) {
            console.log('Server-side results found:', result.results.length);
            // Store the first result as the last scanned result
            lastScannedResult = result.results[0];
            // Show success message for each detected QR code
            result.results.forEach(qrResult => {
                showScanNotification(qrResult);
            });
            console.log('Displaying server-side results...');
            displayResults(result.results);
        } else {
            console.log('No QR codes found in this frame or server error');
            if (!result.success) {
                console.error('Server error:', result.error);
            }
        }
        
    } catch (error) {
        console.error('Error in captureAndScan:', error);
    }
}

// URL Analysis
async function analyzeUrl() {
    const url = urlInput.value.trim();
    
    if (!url) {
        showMessage('Please enter a URL to analyze.', 'error');
        return;
    }
    
    if (!isValidUrl(url)) {
        showMessage('Please enter a valid URL.', 'error');
        return;
    }
    
    showLoading(true);
    
    try {
        const response = await fetch('/analyze_url', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        });
        
        const result = await response.json();
        
        if (result.success) {
            displayResults([result]);
            urlInput.value = '';
        } else {
            showMessage('Error analyzing URL: ' + result.error, 'error');
        }
        
    } catch (error) {
        console.error('Error analyzing URL:', error);
        showMessage('Error analyzing URL. Please try again.', 'error');
    } finally {
        showLoading(false);
    }
}

// Display Results
function displayResults(results) {
    console.log('displayResults called with:', results);
    console.log('Current scannedHistory length:', scannedHistory.length);
    
    // Add new results to history
    results.forEach(result => {
        console.log('Processing result:', result);
        // Check if this URL was already scanned to avoid duplicates
        const existingIndex = scannedHistory.findIndex(item => item.url === result.url);
        if (existingIndex >= 0) {
            // Update existing entry with new timestamp
            scannedHistory[existingIndex] = { ...result, timestamp: new Date() };
            console.log('Updated existing entry at index:', existingIndex);
        } else {
            // Add new entry
            scannedHistory.push({ ...result, timestamp: new Date() });
            console.log('Added new entry. New history length:', scannedHistory.length);
        }
    });
    
    // Sort by timestamp (newest first)
    scannedHistory.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    
    // Limit history to prevent memory issues
    if (scannedHistory.length > 50) {
        scannedHistory = scannedHistory.slice(0, 50);
    }
    
    console.log('Updated scannedHistory:', scannedHistory);
    
    // Update both tab views
    updateLatestResults();
    updateHistoryResults();
}

function updateLatestResults() {
    if (!latestResultsContainer) return;
    
    latestResultsContainer.innerHTML = '';
    
    if (scannedHistory.length === 0) {
        latestResultsContainer.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">
                    <i class="fas fa-qrcode"></i>
                </div>
                <h4>No recent scans</h4>
                <p>Start scanning to see the latest result here</p>
            </div>
        `;
        return;
    }
    
    // Show only the most recent result
    const latestResult = scannedHistory[0];
    const resultElement = createResultElement(latestResult, 0);
    latestResultsContainer.appendChild(resultElement);
}

function updateHistoryResults() {
    if (!historyResultsContainer) return;
    
    historyResultsContainer.innerHTML = '';
    
    if (scannedHistory.length === 0) {
        historyResultsContainer.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">
                    <i class="fas fa-history"></i>
                </div>
                <h4>No scan history</h4>
                <p>Your scan history will appear here</p>
            </div>
        `;
        return;
    }
    
    // Show all results (limited to prevent overflow)
    const maxDisplay = Math.min(scannedHistory.length, 20);
    for (let i = 0; i < maxDisplay; i++) {
        const resultElement = createResultElement(scannedHistory[i], i);
        historyResultsContainer.appendChild(resultElement);
    }
    
    // Show count if there are more results
    if (scannedHistory.length > 20) {
        const moreResults = document.createElement('div');
        moreResults.className = 'more-results-info';
        moreResults.innerHTML = `
            <div style="text-align: center; padding: 1rem; color: #6b7280; font-size: 0.9rem;">
                <i class="fas fa-info-circle"></i>
                Showing latest 20 of ${scannedHistory.length} total scans
            </div>
        `;
        historyResultsContainer.appendChild(moreResults);
    }
}

function createResultElement(result, index) {
    const div = document.createElement('div');
    div.className = `result-item ${result.is_malicious ? 'malicious' : 'safe'}`;
    
    // Format timestamp
    const timestamp = result.timestamp ? new Date(result.timestamp).toLocaleString() : 'Just now';
    
    // Create terminal-style output
    div.innerHTML = `
        <div class="result-header">
            <div class="result-meta">
                <span class="scan-time"><i class="fas fa-clock"></i> ${timestamp}</span>
                ${index === 0 ? '<span class="latest-badge">Latest</span>' : ''}
            </div>
        </div>
        
        <div class="terminal-output">
            <div class="terminal-line">
                <span class="terminal-prompt">🔗 URL:</span>
                <span class="terminal-url">${result.url}</span>
            </div>
            <div class="terminal-line">
                <span class="terminal-indent">   Predicted Label:</span>
                <span class="terminal-value ${result.is_malicious ? 'malicious-text' : 'safe-text'}">${result.prediction}</span>
            </div>
                    <div class="terminal-line">
                        <span class="terminal-indent">   Malicious Probability:</span>
                        <span class="terminal-value">${parseFloat(result.confidence).toFixed(2)}%</span>
                    </div>
        </div>
    `;
    
    return div;
}

// Utility Functions
function isValidUrl(string) {
    try {
        new URL(string);
        return true;
    } catch (_) {
        return false;
    }
}

function showLoading(show) {
    if (show) {
        loadingOverlay.classList.add('show');
    } else {
        loadingOverlay.classList.remove('show');
    }
}

function showMessage(message, type = 'info') {
    // Create toast notification
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    
    document.body.appendChild(toast);
    
    // Animate in
    setTimeout(() => {
        toast.style.transform = 'translateX(0)';
    }, 100);
    
    // Remove after 4 seconds (longer for success messages)
    const duration = type === 'success' ? 4000 : 3000;
    setTimeout(() => {
        toast.style.transform = 'translateX(100%)';
        setTimeout(() => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 300);
    }, duration);
}

function showScanNotification(result) {
    // Create a special notification for QR scan results
    const notification = document.createElement('div');
    notification.className = 'scan-notification';
    
    const statusIcon = result.is_malicious ? '⚠️' : '✅';
    const statusText = result.is_malicious ? 'MALICIOUS' : 'SAFE';
    const statusClass = result.is_malicious ? 'malicious' : 'safe';
    
    notification.innerHTML = `
        <div class="scan-notification-header">
            <span class="scan-icon">${statusIcon}</span>
            <span class="scan-status ${statusClass}">${statusText}</span>
            <span class="scan-confidence">${parseFloat(result.confidence).toFixed(2)}%</span>
        </div>
        <div class="scan-url">${result.url}</div>
        <div class="scan-details">
            <span class="scan-prediction">Prediction: ${result.prediction}</span>
        </div>
    `;
    
    // Style the notification
    Object.assign(notification.style, {
        position: 'fixed',
        top: '20px',
        right: '20px',
        background: result.is_malicious ? '#dc2626' : '#16a34a',
        color: 'white',
        padding: '1rem',
        borderRadius: '8px',
        boxShadow: '0 4px 12px rgba(0, 0, 0, 0.15)',
        zIndex: '10000',
        transform: 'translateX(100%)',
        transition: 'transform 0.3s ease',
        maxWidth: '400px',
        wordWrap: 'break-word'
    });
    
    document.body.appendChild(notification);
    
    // Animate in
    setTimeout(() => {
        notification.style.transform = 'translateX(0)';
    }, 100);
    
    // Remove after 5 seconds
    setTimeout(() => {
        notification.style.transform = 'translateX(100%)';
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 300);
    }, 5000);
}

// Handle page visibility change (pause scanning when tab is not visible)
document.addEventListener('visibilitychange', function() {
    if (document.hidden && isScanning) {
        stopScanning();
    } else if (!document.hidden && isScanning) {
        startScanning();
    }
});

// Cleanup on page unload
window.addEventListener('beforeunload', function() {
    if (cameraStream) {
        cameraStream.getTracks().forEach(track => track.stop());
    }
});