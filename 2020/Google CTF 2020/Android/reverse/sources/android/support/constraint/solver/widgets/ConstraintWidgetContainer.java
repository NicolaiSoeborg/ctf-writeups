package android.support.constraint.solver.widgets;

import android.support.constraint.solver.LinearSystem;
import android.support.constraint.solver.Metrics;
import android.support.constraint.solver.widgets.ConstraintAnchor;
import android.support.constraint.solver.widgets.ConstraintWidget;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ConstraintWidgetContainer extends WidgetContainer {
    private static final boolean DEBUG = false;
    static final boolean DEBUG_GRAPH = false;
    private static final boolean DEBUG_LAYOUT = false;
    private static final int MAX_ITERATIONS = 8;
    private static final boolean USE_SNAPSHOT = true;
    int mDebugSolverPassCount;
    public boolean mGroupsWrapOptimized;
    private boolean mHeightMeasuredTooSmall;
    ChainHead[] mHorizontalChainsArray;
    int mHorizontalChainsSize;
    public boolean mHorizontalWrapOptimized;
    private boolean mIsRtl;
    private int mOptimizationLevel;
    int mPaddingBottom;
    int mPaddingLeft;
    int mPaddingRight;
    int mPaddingTop;
    public boolean mSkipSolver;
    private Snapshot mSnapshot;
    protected LinearSystem mSystem;
    ChainHead[] mVerticalChainsArray;
    int mVerticalChainsSize;
    public boolean mVerticalWrapOptimized;
    public List<ConstraintWidgetGroup> mWidgetGroups;
    private boolean mWidthMeasuredTooSmall;
    public int mWrapFixedHeight;
    public int mWrapFixedWidth;

    public void fillMetrics(Metrics metrics) {
        this.mSystem.fillMetrics(metrics);
    }

    public ConstraintWidgetContainer() {
        this.mIsRtl = false;
        this.mSystem = new LinearSystem();
        this.mHorizontalChainsSize = 0;
        this.mVerticalChainsSize = 0;
        this.mVerticalChainsArray = new ChainHead[4];
        this.mHorizontalChainsArray = new ChainHead[4];
        this.mWidgetGroups = new ArrayList();
        this.mGroupsWrapOptimized = false;
        this.mHorizontalWrapOptimized = false;
        this.mVerticalWrapOptimized = false;
        this.mWrapFixedWidth = 0;
        this.mWrapFixedHeight = 0;
        this.mOptimizationLevel = 7;
        this.mSkipSolver = false;
        this.mWidthMeasuredTooSmall = false;
        this.mHeightMeasuredTooSmall = false;
        this.mDebugSolverPassCount = 0;
    }

    public ConstraintWidgetContainer(int x, int y, int width, int height) {
        super(x, y, width, height);
        this.mIsRtl = false;
        this.mSystem = new LinearSystem();
        this.mHorizontalChainsSize = 0;
        this.mVerticalChainsSize = 0;
        this.mVerticalChainsArray = new ChainHead[4];
        this.mHorizontalChainsArray = new ChainHead[4];
        this.mWidgetGroups = new ArrayList();
        this.mGroupsWrapOptimized = false;
        this.mHorizontalWrapOptimized = false;
        this.mVerticalWrapOptimized = false;
        this.mWrapFixedWidth = 0;
        this.mWrapFixedHeight = 0;
        this.mOptimizationLevel = 7;
        this.mSkipSolver = false;
        this.mWidthMeasuredTooSmall = false;
        this.mHeightMeasuredTooSmall = false;
        this.mDebugSolverPassCount = 0;
    }

    public ConstraintWidgetContainer(int width, int height) {
        super(width, height);
        this.mIsRtl = false;
        this.mSystem = new LinearSystem();
        this.mHorizontalChainsSize = 0;
        this.mVerticalChainsSize = 0;
        this.mVerticalChainsArray = new ChainHead[4];
        this.mHorizontalChainsArray = new ChainHead[4];
        this.mWidgetGroups = new ArrayList();
        this.mGroupsWrapOptimized = false;
        this.mHorizontalWrapOptimized = false;
        this.mVerticalWrapOptimized = false;
        this.mWrapFixedWidth = 0;
        this.mWrapFixedHeight = 0;
        this.mOptimizationLevel = 7;
        this.mSkipSolver = false;
        this.mWidthMeasuredTooSmall = false;
        this.mHeightMeasuredTooSmall = false;
        this.mDebugSolverPassCount = 0;
    }

    public void setOptimizationLevel(int value) {
        this.mOptimizationLevel = value;
    }

    public int getOptimizationLevel() {
        return this.mOptimizationLevel;
    }

    public boolean optimizeFor(int feature) {
        if ((this.mOptimizationLevel & feature) == feature) {
            return USE_SNAPSHOT;
        }
        return false;
    }

    @Override // android.support.constraint.solver.widgets.ConstraintWidget
    public String getType() {
        return "ConstraintLayout";
    }

    @Override // android.support.constraint.solver.widgets.WidgetContainer, android.support.constraint.solver.widgets.ConstraintWidget
    public void reset() {
        this.mSystem.reset();
        this.mPaddingLeft = 0;
        this.mPaddingRight = 0;
        this.mPaddingTop = 0;
        this.mPaddingBottom = 0;
        this.mWidgetGroups.clear();
        this.mSkipSolver = false;
        super.reset();
    }

    public boolean isWidthMeasuredTooSmall() {
        return this.mWidthMeasuredTooSmall;
    }

    public boolean isHeightMeasuredTooSmall() {
        return this.mHeightMeasuredTooSmall;
    }

    public boolean addChildrenToSolver(LinearSystem system) {
        addToSolver(system);
        int count = this.mChildren.size();
        for (int i = 0; i < count; i++) {
            ConstraintWidget widget = (ConstraintWidget) this.mChildren.get(i);
            if (widget instanceof ConstraintWidgetContainer) {
                ConstraintWidget.DimensionBehaviour horizontalBehaviour = widget.mListDimensionBehaviors[0];
                ConstraintWidget.DimensionBehaviour verticalBehaviour = widget.mListDimensionBehaviors[1];
                if (horizontalBehaviour == ConstraintWidget.DimensionBehaviour.WRAP_CONTENT) {
                    widget.setHorizontalDimensionBehaviour(ConstraintWidget.DimensionBehaviour.FIXED);
                }
                if (verticalBehaviour == ConstraintWidget.DimensionBehaviour.WRAP_CONTENT) {
                    widget.setVerticalDimensionBehaviour(ConstraintWidget.DimensionBehaviour.FIXED);
                }
                widget.addToSolver(system);
                if (horizontalBehaviour == ConstraintWidget.DimensionBehaviour.WRAP_CONTENT) {
                    widget.setHorizontalDimensionBehaviour(horizontalBehaviour);
                }
                if (verticalBehaviour == ConstraintWidget.DimensionBehaviour.WRAP_CONTENT) {
                    widget.setVerticalDimensionBehaviour(verticalBehaviour);
                }
            } else {
                Optimizer.checkMatchParent(this, system, widget);
                widget.addToSolver(system);
            }
        }
        if (this.mHorizontalChainsSize > 0) {
            Chain.applyChainConstraints(this, system, 0);
        }
        if (this.mVerticalChainsSize > 0) {
            Chain.applyChainConstraints(this, system, 1);
        }
        return USE_SNAPSHOT;
    }

    public void updateChildrenFromSolver(LinearSystem system, boolean[] flags) {
        flags[2] = false;
        updateFromSolver(system);
        int count = this.mChildren.size();
        for (int i = 0; i < count; i++) {
            ConstraintWidget widget = (ConstraintWidget) this.mChildren.get(i);
            widget.updateFromSolver(system);
            if (widget.mListDimensionBehaviors[0] == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT && widget.getWidth() < widget.getWrapWidth()) {
                flags[2] = USE_SNAPSHOT;
            }
            if (widget.mListDimensionBehaviors[1] == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT && widget.getHeight() < widget.getWrapHeight()) {
                flags[2] = USE_SNAPSHOT;
            }
        }
    }

    public void setPadding(int left, int top, int right, int bottom) {
        this.mPaddingLeft = left;
        this.mPaddingTop = top;
        this.mPaddingRight = right;
        this.mPaddingBottom = bottom;
    }

    public void setRtl(boolean isRtl) {
        this.mIsRtl = isRtl;
    }

    public boolean isRtl() {
        return this.mIsRtl;
    }

    @Override // android.support.constraint.solver.widgets.ConstraintWidget
    public void analyze(int optimizationLevel) {
        super.analyze(optimizationLevel);
        int count = this.mChildren.size();
        for (int i = 0; i < count; i++) {
            ((ConstraintWidget) this.mChildren.get(i)).analyze(optimizationLevel);
        }
    }

    /* JADX WARNING: Removed duplicated region for block: B:113:0x0291  */
    /* JADX WARNING: Removed duplicated region for block: B:116:0x02ae  */
    /* JADX WARNING: Removed duplicated region for block: B:118:0x02bd  */
    /* JADX WARNING: Removed duplicated region for block: B:131:0x0307  */
    /* JADX WARNING: Removed duplicated region for block: B:75:0x01a2  */
    /* JADX WARNING: Removed duplicated region for block: B:76:0x01aa  */
    /* JADX WARNING: Removed duplicated region for block: B:91:0x01f7  */
    @Override // android.support.constraint.solver.widgets.WidgetContainer
    public void layout() {
        int prey;
        boolean wrap_override;
        int groupSize;
        int prey2;
        boolean needsSolving;
        int count;
        boolean maxX;
        int width;
        int height;
        boolean needsSolving2;
        Exception e;
        int prex = this.mX;
        int prey3 = this.mY;
        int prew = Math.max(0, getWidth());
        int preh = Math.max(0, getHeight());
        this.mWidthMeasuredTooSmall = false;
        this.mHeightMeasuredTooSmall = false;
        if (this.mParent != null) {
            if (this.mSnapshot == null) {
                this.mSnapshot = new Snapshot(this);
            }
            this.mSnapshot.updateFrom(this);
            setX(this.mPaddingLeft);
            setY(this.mPaddingTop);
            resetAnchors();
            resetSolverVariables(this.mSystem.getCache());
        } else {
            this.mX = 0;
            this.mY = 0;
        }
        int i = 32;
        if (this.mOptimizationLevel != 0) {
            if (!optimizeFor(8)) {
                optimizeReset();
            }
            if (!optimizeFor(32)) {
                optimize();
            }
            this.mSystem.graphOptimizer = USE_SNAPSHOT;
        } else {
            this.mSystem.graphOptimizer = false;
        }
        ConstraintWidget.DimensionBehaviour originalVerticalDimensionBehaviour = this.mListDimensionBehaviors[1];
        ConstraintWidget.DimensionBehaviour originalHorizontalDimensionBehaviour = this.mListDimensionBehaviors[0];
        resetChains();
        if (this.mWidgetGroups.size() == 0) {
            this.mWidgetGroups.clear();
            this.mWidgetGroups.add(0, new ConstraintWidgetGroup(this.mChildren));
        }
        int groupSize2 = this.mWidgetGroups.size();
        List<ConstraintWidget> allChildren = this.mChildren;
        boolean hasWrapContent = (getHorizontalDimensionBehaviour() == ConstraintWidget.DimensionBehaviour.WRAP_CONTENT || getVerticalDimensionBehaviour() == ConstraintWidget.DimensionBehaviour.WRAP_CONTENT) ? USE_SNAPSHOT : false;
        boolean wrap_override2 = false;
        int groupIndex = 0;
        while (groupIndex < groupSize2 && !this.mSkipSolver) {
            if (this.mWidgetGroups.get(groupIndex).mSkipSolver) {
                prey = prey3;
                groupSize = groupSize2;
            } else {
                if (optimizeFor(i)) {
                    if (getHorizontalDimensionBehaviour() == ConstraintWidget.DimensionBehaviour.FIXED && getVerticalDimensionBehaviour() == ConstraintWidget.DimensionBehaviour.FIXED) {
                        this.mChildren = (ArrayList) this.mWidgetGroups.get(groupIndex).getWidgetsToSolve();
                    } else {
                        this.mChildren = (ArrayList) this.mWidgetGroups.get(groupIndex).mConstrainedGroup;
                    }
                }
                resetChains();
                int count2 = this.mChildren.size();
                int countSolve = 0;
                int i2 = 0;
                while (i2 < count2) {
                    ConstraintWidget widget = (ConstraintWidget) this.mChildren.get(i2);
                    if ((widget instanceof WidgetContainer) != 0) {
                        ((WidgetContainer) widget).layout();
                    }
                    i2++;
                    countSolve = countSolve;
                    groupSize2 = groupSize2;
                }
                int countSolve2 = countSolve;
                groupSize = groupSize2;
                boolean needsSolving3 = USE_SNAPSHOT;
                while (needsSolving3) {
                    int countSolve3 = countSolve2 + 1;
                    try {
                        this.mSystem.reset();
                        resetChains();
                        createObjectVariables(this.mSystem);
                        int i3 = 0;
                        while (i3 < count2) {
                            needsSolving = needsSolving3;
                            try {
                                wrap_override = wrap_override2;
                                try {
                                    ((ConstraintWidget) this.mChildren.get(i3)).createObjectVariables(this.mSystem);
                                    i3++;
                                    needsSolving3 = needsSolving;
                                    wrap_override2 = wrap_override;
                                } catch (Exception e2) {
                                    e = e2;
                                    e = e;
                                    e.printStackTrace();
                                    PrintStream printStream = System.out;
                                    StringBuilder sb = new StringBuilder();
                                    prey2 = prey3;
                                    sb.append("EXCEPTION : ");
                                    sb.append(e);
                                    printStream.println(sb.toString());
                                    if (needsSolving) {
                                    }
                                    boolean needsSolving4 = false;
                                    if (hasWrapContent) {
                                    }
                                    count = count2;
                                    wrap_override2 = wrap_override;
                                    maxX = false;
                                    width = Math.max(this.mMinWidth, getWidth());
                                    if (width > getWidth()) {
                                    }
                                    height = Math.max(this.mMinHeight, getHeight());
                                    if (height > getHeight()) {
                                    }
                                    if (wrap_override2) {
                                    }
                                    countSolve2 = countSolve3;
                                    prey3 = prey2;
                                    count2 = count;
                                }
                            } catch (Exception e3) {
                                wrap_override = wrap_override2;
                                e = e3;
                                e.printStackTrace();
                                PrintStream printStream2 = System.out;
                                StringBuilder sb2 = new StringBuilder();
                                prey2 = prey3;
                                sb2.append("EXCEPTION : ");
                                sb2.append(e);
                                printStream2.println(sb2.toString());
                                if (needsSolving) {
                                }
                                boolean needsSolving42 = false;
                                if (hasWrapContent) {
                                }
                                count = count2;
                                wrap_override2 = wrap_override;
                                maxX = false;
                                width = Math.max(this.mMinWidth, getWidth());
                                if (width > getWidth()) {
                                }
                                height = Math.max(this.mMinHeight, getHeight());
                                if (height > getHeight()) {
                                }
                                if (wrap_override2) {
                                }
                                countSolve2 = countSolve3;
                                prey3 = prey2;
                                count2 = count;
                            }
                        }
                        wrap_override = wrap_override2;
                        boolean needsSolving5 = addChildrenToSolver(this.mSystem);
                        if (needsSolving5) {
                            try {
                                this.mSystem.minimize();
                            } catch (Exception e4) {
                                e = e4;
                                needsSolving = needsSolving5;
                            }
                        }
                        prey2 = prey3;
                        needsSolving = needsSolving5;
                    } catch (Exception e5) {
                        needsSolving = needsSolving3;
                        wrap_override = wrap_override2;
                        e = e5;
                        e.printStackTrace();
                        PrintStream printStream22 = System.out;
                        StringBuilder sb22 = new StringBuilder();
                        prey2 = prey3;
                        sb22.append("EXCEPTION : ");
                        sb22.append(e);
                        printStream22.println(sb22.toString());
                        if (needsSolving) {
                        }
                        boolean needsSolving422 = false;
                        if (hasWrapContent) {
                        }
                        count = count2;
                        wrap_override2 = wrap_override;
                        maxX = false;
                        width = Math.max(this.mMinWidth, getWidth());
                        if (width > getWidth()) {
                        }
                        height = Math.max(this.mMinHeight, getHeight());
                        if (height > getHeight()) {
                        }
                        if (wrap_override2) {
                        }
                        countSolve2 = countSolve3;
                        prey3 = prey2;
                        count2 = count;
                    }
                    if (needsSolving) {
                        updateFromSolver(this.mSystem);
                        int i4 = 0;
                        while (true) {
                            if (i4 >= count2) {
                                break;
                            }
                            ConstraintWidget widget2 = (ConstraintWidget) this.mChildren.get(i4);
                            if (widget2.mListDimensionBehaviors[0] != ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT || widget2.getWidth() >= widget2.getWrapWidth()) {
                                if (widget2.mListDimensionBehaviors[1] == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT && widget2.getHeight() < widget2.getWrapHeight()) {
                                    Optimizer.flags[2] = USE_SNAPSHOT;
                                    break;
                                }
                                i4++;
                            } else {
                                Optimizer.flags[2] = USE_SNAPSHOT;
                                break;
                            }
                        }
                    } else {
                        updateChildrenFromSolver(this.mSystem, Optimizer.flags);
                    }
                    boolean needsSolving4222 = false;
                    if (hasWrapContent || countSolve3 >= 8 || !Optimizer.flags[2]) {
                        count = count2;
                        wrap_override2 = wrap_override;
                        maxX = false;
                    } else {
                        int maxY = 0;
                        int maxX2 = 0;
                        int i5 = 0;
                        while (i5 < count2) {
                            ConstraintWidget widget3 = (ConstraintWidget) this.mChildren.get(i5);
                            maxX2 = Math.max(maxX2, widget3.mX + widget3.getWidth());
                            maxY = Math.max(maxY, widget3.mY + widget3.getHeight());
                            i5++;
                            needsSolving4222 = needsSolving4222;
                            count2 = count2;
                        }
                        count = count2;
                        int maxX3 = Math.max(this.mMinWidth, maxX2);
                        int maxY2 = Math.max(this.mMinHeight, maxY);
                        if (originalHorizontalDimensionBehaviour != ConstraintWidget.DimensionBehaviour.WRAP_CONTENT || getWidth() >= maxX3) {
                            wrap_override2 = wrap_override;
                            needsSolving2 = needsSolving4222;
                        } else {
                            setWidth(maxX3);
                            this.mListDimensionBehaviors[0] = ConstraintWidget.DimensionBehaviour.WRAP_CONTENT;
                            wrap_override2 = USE_SNAPSHOT;
                            needsSolving2 = USE_SNAPSHOT;
                        }
                        if (originalVerticalDimensionBehaviour != ConstraintWidget.DimensionBehaviour.WRAP_CONTENT || getHeight() >= maxY2) {
                            maxX = needsSolving2;
                        } else {
                            setHeight(maxY2);
                            this.mListDimensionBehaviors[1] = ConstraintWidget.DimensionBehaviour.WRAP_CONTENT;
                            wrap_override2 = USE_SNAPSHOT;
                            maxX = USE_SNAPSHOT;
                        }
                    }
                    width = Math.max(this.mMinWidth, getWidth());
                    if (width > getWidth()) {
                        setWidth(width);
                        this.mListDimensionBehaviors[0] = ConstraintWidget.DimensionBehaviour.FIXED;
                        wrap_override2 = USE_SNAPSHOT;
                        maxX = USE_SNAPSHOT;
                    }
                    height = Math.max(this.mMinHeight, getHeight());
                    if (height > getHeight()) {
                        setHeight(height);
                        this.mListDimensionBehaviors[1] = ConstraintWidget.DimensionBehaviour.FIXED;
                        wrap_override2 = USE_SNAPSHOT;
                        maxX = USE_SNAPSHOT;
                    }
                    if (wrap_override2) {
                        boolean needsSolving6 = maxX;
                        if (this.mListDimensionBehaviors[0] == ConstraintWidget.DimensionBehaviour.WRAP_CONTENT && prew > 0 && getWidth() > prew) {
                            this.mWidthMeasuredTooSmall = USE_SNAPSHOT;
                            wrap_override2 = USE_SNAPSHOT;
                            this.mListDimensionBehaviors[0] = ConstraintWidget.DimensionBehaviour.FIXED;
                            setWidth(prew);
                            needsSolving6 = true;
                        }
                        if (this.mListDimensionBehaviors[1] != ConstraintWidget.DimensionBehaviour.WRAP_CONTENT || preh <= 0 || getHeight() <= preh) {
                            needsSolving3 = needsSolving6;
                        } else {
                            this.mHeightMeasuredTooSmall = USE_SNAPSHOT;
                            wrap_override2 = USE_SNAPSHOT;
                            this.mListDimensionBehaviors[1] = ConstraintWidget.DimensionBehaviour.FIXED;
                            setHeight(preh);
                            needsSolving3 = true;
                        }
                    } else {
                        needsSolving3 = maxX;
                    }
                    countSolve2 = countSolve3;
                    prey3 = prey2;
                    count2 = count;
                }
                prey = prey3;
                wrap_override = wrap_override2;
                this.mWidgetGroups.get(groupIndex).updateUnresolvedWidgets();
            }
            groupIndex++;
            groupSize2 = groupSize;
            prey3 = prey;
            i = 32;
        }
        this.mChildren = (ArrayList) allChildren;
        if (this.mParent != null) {
            int width2 = Math.max(this.mMinWidth, getWidth());
            int height2 = Math.max(this.mMinHeight, getHeight());
            this.mSnapshot.applyTo(this);
            setWidth(this.mPaddingLeft + width2 + this.mPaddingRight);
            setHeight(this.mPaddingTop + height2 + this.mPaddingBottom);
        } else {
            this.mX = prex;
            this.mY = prey3;
        }
        if (wrap_override2) {
            this.mListDimensionBehaviors[0] = originalHorizontalDimensionBehaviour;
            this.mListDimensionBehaviors[1] = originalVerticalDimensionBehaviour;
        }
        resetSolverVariables(this.mSystem.getCache());
        if (this == getRootConstraintContainer()) {
            updateDrawPosition();
        }
    }

    public void preOptimize() {
        optimizeReset();
        analyze(this.mOptimizationLevel);
    }

    public void solveGraph() {
        ResolutionAnchor leftNode = getAnchor(ConstraintAnchor.Type.LEFT).getResolutionNode();
        ResolutionAnchor topNode = getAnchor(ConstraintAnchor.Type.TOP).getResolutionNode();
        leftNode.resolve(null, 0.0f);
        topNode.resolve(null, 0.0f);
    }

    public void resetGraph() {
        ResolutionAnchor leftNode = getAnchor(ConstraintAnchor.Type.LEFT).getResolutionNode();
        ResolutionAnchor topNode = getAnchor(ConstraintAnchor.Type.TOP).getResolutionNode();
        leftNode.invalidateAnchors();
        topNode.invalidateAnchors();
        leftNode.resolve(null, 0.0f);
        topNode.resolve(null, 0.0f);
    }

    public void optimizeForDimensions(int width, int height) {
        if (!(this.mListDimensionBehaviors[0] == ConstraintWidget.DimensionBehaviour.WRAP_CONTENT || this.mResolutionWidth == null)) {
            this.mResolutionWidth.resolve(width);
        }
        if (this.mListDimensionBehaviors[1] != ConstraintWidget.DimensionBehaviour.WRAP_CONTENT && this.mResolutionHeight != null) {
            this.mResolutionHeight.resolve(height);
        }
    }

    public void optimizeReset() {
        int count = this.mChildren.size();
        resetResolutionNodes();
        for (int i = 0; i < count; i++) {
            ((ConstraintWidget) this.mChildren.get(i)).resetResolutionNodes();
        }
    }

    public void optimize() {
        if (!optimizeFor(8)) {
            analyze(this.mOptimizationLevel);
        }
        solveGraph();
    }

    public boolean handlesInternalConstraints() {
        return false;
    }

    public ArrayList<Guideline> getVerticalGuidelines() {
        ArrayList<Guideline> guidelines = new ArrayList<>();
        int mChildrenSize = this.mChildren.size();
        for (int i = 0; i < mChildrenSize; i++) {
            ConstraintWidget widget = (ConstraintWidget) this.mChildren.get(i);
            if (widget instanceof Guideline) {
                Guideline guideline = (Guideline) widget;
                if (guideline.getOrientation() == 1) {
                    guidelines.add(guideline);
                }
            }
        }
        return guidelines;
    }

    public ArrayList<Guideline> getHorizontalGuidelines() {
        ArrayList<Guideline> guidelines = new ArrayList<>();
        int mChildrenSize = this.mChildren.size();
        for (int i = 0; i < mChildrenSize; i++) {
            ConstraintWidget widget = (ConstraintWidget) this.mChildren.get(i);
            if (widget instanceof Guideline) {
                Guideline guideline = (Guideline) widget;
                if (guideline.getOrientation() == 0) {
                    guidelines.add(guideline);
                }
            }
        }
        return guidelines;
    }

    public LinearSystem getSystem() {
        return this.mSystem;
    }

    private void resetChains() {
        this.mHorizontalChainsSize = 0;
        this.mVerticalChainsSize = 0;
    }

    /* access modifiers changed from: package-private */
    public void addChain(ConstraintWidget constraintWidget, int type) {
        if (type == 0) {
            addHorizontalChain(constraintWidget);
        } else if (type == 1) {
            addVerticalChain(constraintWidget);
        }
    }

    private void addHorizontalChain(ConstraintWidget widget) {
        if (this.mHorizontalChainsSize + 1 >= this.mHorizontalChainsArray.length) {
            this.mHorizontalChainsArray = (ChainHead[]) Arrays.copyOf(this.mHorizontalChainsArray, this.mHorizontalChainsArray.length * 2);
        }
        this.mHorizontalChainsArray[this.mHorizontalChainsSize] = new ChainHead(widget, 0, isRtl());
        this.mHorizontalChainsSize++;
    }

    private void addVerticalChain(ConstraintWidget widget) {
        if (this.mVerticalChainsSize + 1 >= this.mVerticalChainsArray.length) {
            this.mVerticalChainsArray = (ChainHead[]) Arrays.copyOf(this.mVerticalChainsArray, this.mVerticalChainsArray.length * 2);
        }
        this.mVerticalChainsArray[this.mVerticalChainsSize] = new ChainHead(widget, 1, isRtl());
        this.mVerticalChainsSize++;
    }

    public List<ConstraintWidgetGroup> getWidgetGroups() {
        return this.mWidgetGroups;
    }
}
