package android.support.constraint;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.os.Build;
import android.support.constraint.solver.Metrics;
import android.support.constraint.solver.widgets.Analyzer;
import android.support.constraint.solver.widgets.ConstraintAnchor;
import android.support.constraint.solver.widgets.ConstraintWidget;
import android.support.constraint.solver.widgets.ConstraintWidgetContainer;
import android.support.constraint.solver.widgets.Guideline;
import android.support.constraint.solver.widgets.ResolutionAnchor;
import android.util.AttributeSet;
import android.util.Log;
import android.util.SparseArray;
import android.util.SparseIntArray;
import android.view.View;
import android.view.ViewGroup;
import java.util.ArrayList;
import java.util.HashMap;

public class ConstraintLayout extends ViewGroup {
    static final boolean ALLOWS_EMBEDDED = false;
    private static final boolean CACHE_MEASURED_DIMENSION = false;
    private static final boolean DEBUG = false;
    public static final int DESIGN_INFO_ID = 0;
    private static final String TAG = "ConstraintLayout";
    private static final boolean USE_CONSTRAINTS_HELPER = true;
    public static final String VERSION = "ConstraintLayout-1.1.3";
    SparseArray<View> mChildrenByIds = new SparseArray<>();
    private ArrayList<ConstraintHelper> mConstraintHelpers = new ArrayList<>(4);
    private ConstraintSet mConstraintSet = null;
    private int mConstraintSetId = -1;
    private HashMap<String, Integer> mDesignIds = new HashMap<>();
    private boolean mDirtyHierarchy = USE_CONSTRAINTS_HELPER;
    private int mLastMeasureHeight = -1;
    int mLastMeasureHeightMode = 0;
    int mLastMeasureHeightSize = -1;
    private int mLastMeasureWidth = -1;
    int mLastMeasureWidthMode = 0;
    int mLastMeasureWidthSize = -1;
    ConstraintWidgetContainer mLayoutWidget = new ConstraintWidgetContainer();
    private int mMaxHeight = Integer.MAX_VALUE;
    private int mMaxWidth = Integer.MAX_VALUE;
    private Metrics mMetrics;
    private int mMinHeight = 0;
    private int mMinWidth = 0;
    private int mOptimizationLevel = 7;
    private final ArrayList<ConstraintWidget> mVariableDimensionsWidgets = new ArrayList<>(100);

    public void setDesignInformation(int type, Object value1, Object value2) {
        if (type == 0 && (value1 instanceof String) && (value2 instanceof Integer)) {
            if (this.mDesignIds == null) {
                this.mDesignIds = new HashMap<>();
            }
            String name = (String) value1;
            int index = name.indexOf("/");
            if (index != -1) {
                name = name.substring(index + 1);
            }
            this.mDesignIds.put(name, Integer.valueOf(((Integer) value2).intValue()));
        }
    }

    public Object getDesignInformation(int type, Object value) {
        if (type != 0 || !(value instanceof String)) {
            return null;
        }
        String name = (String) value;
        if (this.mDesignIds == null || !this.mDesignIds.containsKey(name)) {
            return null;
        }
        return this.mDesignIds.get(name);
    }

    public ConstraintLayout(Context context) {
        super(context);
        init(null);
    }

    public ConstraintLayout(Context context, AttributeSet attrs) {
        super(context, attrs);
        init(attrs);
    }

    public ConstraintLayout(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        init(attrs);
    }

    public void setId(int id) {
        this.mChildrenByIds.remove(getId());
        super.setId(id);
        this.mChildrenByIds.put(getId(), this);
    }

    private void init(AttributeSet attrs) {
        this.mLayoutWidget.setCompanionWidget(this);
        this.mChildrenByIds.put(getId(), this);
        this.mConstraintSet = null;
        if (attrs != null) {
            TypedArray a = getContext().obtainStyledAttributes(attrs, C0001R.styleable.ConstraintLayout_Layout);
            int N = a.getIndexCount();
            for (int i = 0; i < N; i++) {
                int attr = a.getIndex(i);
                if (attr == C0001R.styleable.ConstraintLayout_Layout_android_minWidth) {
                    this.mMinWidth = a.getDimensionPixelOffset(attr, this.mMinWidth);
                } else if (attr == C0001R.styleable.ConstraintLayout_Layout_android_minHeight) {
                    this.mMinHeight = a.getDimensionPixelOffset(attr, this.mMinHeight);
                } else if (attr == C0001R.styleable.ConstraintLayout_Layout_android_maxWidth) {
                    this.mMaxWidth = a.getDimensionPixelOffset(attr, this.mMaxWidth);
                } else if (attr == C0001R.styleable.ConstraintLayout_Layout_android_maxHeight) {
                    this.mMaxHeight = a.getDimensionPixelOffset(attr, this.mMaxHeight);
                } else if (attr == C0001R.styleable.ConstraintLayout_Layout_layout_optimizationLevel) {
                    this.mOptimizationLevel = a.getInt(attr, this.mOptimizationLevel);
                } else if (attr == C0001R.styleable.ConstraintLayout_Layout_constraintSet) {
                    int id = a.getResourceId(attr, 0);
                    try {
                        this.mConstraintSet = new ConstraintSet();
                        this.mConstraintSet.load(getContext(), id);
                    } catch (Resources.NotFoundException e) {
                        this.mConstraintSet = null;
                    }
                    this.mConstraintSetId = id;
                }
            }
            a.recycle();
        }
        this.mLayoutWidget.setOptimizationLevel(this.mOptimizationLevel);
    }

    @Override // android.view.ViewGroup
    public void addView(View child, int index, ViewGroup.LayoutParams params) {
        super.addView(child, index, params);
        if (Build.VERSION.SDK_INT < 14) {
            onViewAdded(child);
        }
    }

    public void removeView(View view) {
        super.removeView(view);
        if (Build.VERSION.SDK_INT < 14) {
            onViewRemoved(view);
        }
    }

    public void onViewAdded(View view) {
        if (Build.VERSION.SDK_INT >= 14) {
            super.onViewAdded(view);
        }
        ConstraintWidget widget = getViewWidget(view);
        if ((view instanceof Guideline) && !(widget instanceof Guideline)) {
            LayoutParams layoutParams = (LayoutParams) view.getLayoutParams();
            layoutParams.widget = new Guideline();
            layoutParams.isGuideline = USE_CONSTRAINTS_HELPER;
            ((Guideline) layoutParams.widget).setOrientation(layoutParams.orientation);
        }
        if (view instanceof ConstraintHelper) {
            ConstraintHelper helper = (ConstraintHelper) view;
            helper.validateParams();
            ((LayoutParams) view.getLayoutParams()).isHelper = USE_CONSTRAINTS_HELPER;
            if (!this.mConstraintHelpers.contains(helper)) {
                this.mConstraintHelpers.add(helper);
            }
        }
        this.mChildrenByIds.put(view.getId(), view);
        this.mDirtyHierarchy = USE_CONSTRAINTS_HELPER;
    }

    public void onViewRemoved(View view) {
        if (Build.VERSION.SDK_INT >= 14) {
            super.onViewRemoved(view);
        }
        this.mChildrenByIds.remove(view.getId());
        ConstraintWidget widget = getViewWidget(view);
        this.mLayoutWidget.remove(widget);
        this.mConstraintHelpers.remove(view);
        this.mVariableDimensionsWidgets.remove(widget);
        this.mDirtyHierarchy = USE_CONSTRAINTS_HELPER;
    }

    public void setMinWidth(int value) {
        if (value != this.mMinWidth) {
            this.mMinWidth = value;
            requestLayout();
        }
    }

    public void setMinHeight(int value) {
        if (value != this.mMinHeight) {
            this.mMinHeight = value;
            requestLayout();
        }
    }

    public int getMinWidth() {
        return this.mMinWidth;
    }

    public int getMinHeight() {
        return this.mMinHeight;
    }

    public void setMaxWidth(int value) {
        if (value != this.mMaxWidth) {
            this.mMaxWidth = value;
            requestLayout();
        }
    }

    public void setMaxHeight(int value) {
        if (value != this.mMaxHeight) {
            this.mMaxHeight = value;
            requestLayout();
        }
    }

    public int getMaxWidth() {
        return this.mMaxWidth;
    }

    public int getMaxHeight() {
        return this.mMaxHeight;
    }

    private void updateHierarchy() {
        int count = getChildCount();
        boolean recompute = false;
        int i = 0;
        while (true) {
            if (i >= count) {
                break;
            } else if (getChildAt(i).isLayoutRequested()) {
                recompute = USE_CONSTRAINTS_HELPER;
                break;
            } else {
                i++;
            }
        }
        if (recompute) {
            this.mVariableDimensionsWidgets.clear();
            setChildrenConstraints();
        }
    }

    /* JADX INFO: Multiple debug info for r8v3 'layoutParams'  android.support.constraint.ConstraintLayout$LayoutParams: [D('child' android.view.View), D('layoutParams' android.support.constraint.ConstraintLayout$LayoutParams)] */
    /* JADX INFO: Multiple debug info for r5v6 int: [D('resolveGoneRightMargin' int), D('resolvedLeftToRight' int)] */
    /* JADX WARN: Type inference failed for: r33v0, types: [android.support.constraint.ConstraintLayout] */
    /* JADX WARNING: Removed duplicated region for block: B:126:0x0202 A[ADDED_TO_REGION] */
    private void setChildrenConstraints() {
        int helperCount;
        int count;
        int i;
        boolean z;
        int resolveGoneRightMargin;
        int resolveGoneLeftMargin;
        int resolvedLeftToRight;
        int resolvedLeftToRight2;
        int i2;
        LayoutParams layoutParams;
        int helperCount2;
        float resolvedHorizontalBias;
        int resolvedRightToRight;
        ConstraintWidget target;
        ConstraintWidget target2;
        ConstraintWidget target3;
        ConstraintWidget target4;
        int resolvedLeftToLeft;
        int resolvedLeftToRight3;
        int resolvedLeftToLeft2;
        boolean isInEditMode = isInEditMode();
        int count2 = getChildCount();
        boolean z2 = false;
        int i3 = -1;
        if (isInEditMode) {
            for (int i4 = 0; i4 < count2; i4++) {
                View view = getChildAt(i4);
                try {
                    String IdAsString = getResources().getResourceName(view.getId());
                    setDesignInformation(0, IdAsString, Integer.valueOf(view.getId()));
                    int slashIndex = IdAsString.indexOf(47);
                    if (slashIndex != -1) {
                        IdAsString = IdAsString.substring(slashIndex + 1);
                    }
                    getTargetWidget(view.getId()).setDebugName(IdAsString);
                } catch (Resources.NotFoundException e) {
                }
            }
        }
        for (int i5 = 0; i5 < count2; i5++) {
            ConstraintWidget widget = getViewWidget(getChildAt(i5));
            if (widget != null) {
                widget.reset();
            }
        }
        if (((ConstraintLayout) this).mConstraintSetId != -1) {
            for (int i6 = 0; i6 < count2; i6++) {
                View child = getChildAt(i6);
                if (child.getId() == ((ConstraintLayout) this).mConstraintSetId && (child instanceof Constraints)) {
                    ((ConstraintLayout) this).mConstraintSet = ((Constraints) child).getConstraintSet();
                }
            }
        }
        if (((ConstraintLayout) this).mConstraintSet != null) {
            ((ConstraintLayout) this).mConstraintSet.applyToInternal(this);
        }
        ((ConstraintLayout) this).mLayoutWidget.removeAllChildren();
        int helperCount3 = ((ConstraintLayout) this).mConstraintHelpers.size();
        if (helperCount3 > 0) {
            for (int i7 = 0; i7 < helperCount3; i7++) {
                ((ConstraintLayout) this).mConstraintHelpers.get(i7).updatePreLayout(this);
            }
        }
        for (int i8 = 0; i8 < count2; i8++) {
            View child2 = getChildAt(i8);
            if (child2 instanceof Placeholder) {
                ((Placeholder) child2).updatePreLayout(this);
            }
        }
        int i9 = 0;
        while (i9 < count2) {
            View child3 = getChildAt(i9);
            ConstraintWidget widget2 = getViewWidget(child3);
            if (widget2 == null) {
                count = count2;
                z = z2;
                i = i3;
                helperCount = helperCount3;
            } else {
                LayoutParams layoutParams2 = (LayoutParams) child3.getLayoutParams();
                layoutParams2.validate();
                if (layoutParams2.helped) {
                    layoutParams2.helped = z2;
                } else if (isInEditMode) {
                    try {
                        String IdAsString2 = getResources().getResourceName(child3.getId());
                        setDesignInformation(z2 ? 1 : 0, IdAsString2, Integer.valueOf(child3.getId()));
                        getTargetWidget(child3.getId()).setDebugName(IdAsString2.substring(IdAsString2.indexOf("id/") + 3));
                    } catch (Resources.NotFoundException e2) {
                    }
                }
                widget2.setVisibility(child3.getVisibility());
                if (layoutParams2.isInPlaceholder) {
                    widget2.setVisibility(8);
                }
                widget2.setCompanionWidget(child3);
                ((ConstraintLayout) this).mLayoutWidget.add(widget2);
                if (!layoutParams2.verticalDimensionFixed || !layoutParams2.horizontalDimensionFixed) {
                    ((ConstraintLayout) this).mVariableDimensionsWidgets.add(widget2);
                }
                if (layoutParams2.isGuideline) {
                    Guideline guideline = (Guideline) widget2;
                    int resolvedGuideBegin = layoutParams2.resolvedGuideBegin;
                    int resolvedGuideEnd = layoutParams2.resolvedGuideEnd;
                    float resolvedGuidePercent = layoutParams2.resolvedGuidePercent;
                    if (Build.VERSION.SDK_INT < 17) {
                        resolvedGuideBegin = layoutParams2.guideBegin;
                        resolvedGuideEnd = layoutParams2.guideEnd;
                        resolvedGuidePercent = layoutParams2.guidePercent;
                    }
                    if (resolvedGuidePercent != -1.0f) {
                        guideline.setGuidePercent(resolvedGuidePercent);
                    } else if (resolvedGuideBegin != i3) {
                        guideline.setGuideBegin(resolvedGuideBegin);
                    } else if (resolvedGuideEnd != i3) {
                        guideline.setGuideEnd(resolvedGuideEnd);
                    }
                } else if (!(layoutParams2.leftToLeft == i3 && layoutParams2.leftToRight == i3 && layoutParams2.rightToLeft == i3 && layoutParams2.rightToRight == i3 && layoutParams2.startToStart == i3 && layoutParams2.startToEnd == i3 && layoutParams2.endToStart == i3 && layoutParams2.endToEnd == i3 && layoutParams2.topToTop == i3 && layoutParams2.topToBottom == i3 && layoutParams2.bottomToTop == i3 && layoutParams2.bottomToBottom == i3 && layoutParams2.baselineToBaseline == i3 && layoutParams2.editorAbsoluteX == i3 && layoutParams2.editorAbsoluteY == i3 && layoutParams2.circleConstraint == i3 && layoutParams2.width != i3 && layoutParams2.height != i3)) {
                    int resolvedLeftToLeft3 = layoutParams2.resolvedLeftToLeft;
                    int resolvedLeftToRight4 = layoutParams2.resolvedLeftToRight;
                    int resolvedRightToLeft = layoutParams2.resolvedRightToLeft;
                    int resolvedRightToRight2 = layoutParams2.resolvedRightToRight;
                    int resolveGoneLeftMargin2 = layoutParams2.resolveGoneLeftMargin;
                    int resolveGoneRightMargin2 = layoutParams2.resolveGoneRightMargin;
                    float resolvedHorizontalBias2 = layoutParams2.resolvedHorizontalBias;
                    count = count2;
                    if (Build.VERSION.SDK_INT < 17) {
                        int resolvedLeftToLeft4 = layoutParams2.leftToLeft;
                        int resolvedLeftToRight5 = layoutParams2.leftToRight;
                        resolvedRightToLeft = layoutParams2.rightToLeft;
                        resolvedRightToRight2 = layoutParams2.rightToRight;
                        int i10 = layoutParams2.goneLeftMargin;
                        int resolvedLeftToRight6 = layoutParams2.goneRightMargin;
                        resolvedHorizontalBias2 = layoutParams2.horizontalBias;
                        if (resolvedLeftToLeft4 == -1 && resolvedLeftToRight5 == -1) {
                            resolvedLeftToLeft2 = resolvedLeftToLeft4;
                            if (layoutParams2.startToStart != -1) {
                                resolvedLeftToRight2 = layoutParams2.startToStart;
                                resolvedLeftToLeft = resolvedLeftToRight5;
                                if (resolvedRightToLeft == -1 || resolvedRightToRight2 != -1) {
                                    resolvedLeftToRight3 = resolvedLeftToLeft;
                                } else {
                                    resolvedLeftToRight3 = resolvedLeftToLeft;
                                    if (layoutParams2.endToStart != -1) {
                                        resolvedRightToLeft = layoutParams2.endToStart;
                                    } else if (layoutParams2.endToEnd != -1) {
                                        resolvedRightToRight2 = layoutParams2.endToEnd;
                                    }
                                }
                                resolveGoneRightMargin = resolvedLeftToRight6;
                                resolveGoneLeftMargin = i10;
                                i2 = -1;
                                resolvedLeftToRight = resolvedLeftToRight3;
                            } else if (layoutParams2.startToEnd != -1) {
                                resolvedLeftToLeft = layoutParams2.startToEnd;
                                resolvedLeftToRight2 = resolvedLeftToLeft2;
                                if (resolvedRightToLeft == -1) {
                                }
                                resolvedLeftToRight3 = resolvedLeftToLeft;
                                resolveGoneRightMargin = resolvedLeftToRight6;
                                resolveGoneLeftMargin = i10;
                                i2 = -1;
                                resolvedLeftToRight = resolvedLeftToRight3;
                            }
                        } else {
                            resolvedLeftToLeft2 = resolvedLeftToLeft4;
                        }
                        resolvedLeftToLeft = resolvedLeftToRight5;
                        resolvedLeftToRight2 = resolvedLeftToLeft2;
                        if (resolvedRightToLeft == -1) {
                        }
                        resolvedLeftToRight3 = resolvedLeftToLeft;
                        resolveGoneRightMargin = resolvedLeftToRight6;
                        resolveGoneLeftMargin = i10;
                        i2 = -1;
                        resolvedLeftToRight = resolvedLeftToRight3;
                    } else {
                        i2 = -1;
                        resolveGoneLeftMargin = resolveGoneLeftMargin2;
                        resolvedLeftToRight2 = resolvedLeftToLeft3;
                        resolveGoneRightMargin = resolveGoneRightMargin2;
                        resolvedLeftToRight = resolvedLeftToRight4;
                    }
                    if (layoutParams2.circleConstraint != i2) {
                        ConstraintWidget target5 = getTargetWidget(layoutParams2.circleConstraint);
                        if (target5 != null) {
                            widget2.connectCircularConstraint(target5, layoutParams2.circleAngle, layoutParams2.circleRadius);
                        }
                        helperCount = helperCount3;
                        layoutParams = layoutParams2;
                    } else {
                        if (resolvedLeftToRight2 != -1) {
                            ConstraintWidget target6 = getTargetWidget(resolvedLeftToRight2);
                            if (target6 != null) {
                                resolvedHorizontalBias = resolvedHorizontalBias2;
                                resolvedRightToRight = resolvedRightToRight2;
                                helperCount = helperCount3;
                                helperCount2 = resolvedRightToLeft;
                                layoutParams = layoutParams2;
                                widget2.immediateConnect(ConstraintAnchor.Type.LEFT, target6, ConstraintAnchor.Type.LEFT, layoutParams2.leftMargin, resolveGoneLeftMargin);
                            } else {
                                helperCount = helperCount3;
                                resolvedHorizontalBias = resolvedHorizontalBias2;
                                resolvedRightToRight = resolvedRightToRight2;
                                helperCount2 = resolvedRightToLeft;
                                layoutParams = layoutParams2;
                            }
                        } else {
                            helperCount = helperCount3;
                            resolvedHorizontalBias = resolvedHorizontalBias2;
                            resolvedRightToRight = resolvedRightToRight2;
                            helperCount2 = resolvedRightToLeft;
                            layoutParams = layoutParams2;
                            if (!(resolvedLeftToRight == -1 || (target4 = getTargetWidget(resolvedLeftToRight)) == null)) {
                                widget2.immediateConnect(ConstraintAnchor.Type.LEFT, target4, ConstraintAnchor.Type.RIGHT, layoutParams.leftMargin, resolveGoneLeftMargin);
                            }
                        }
                        if (helperCount2 != -1) {
                            ConstraintWidget target7 = getTargetWidget(helperCount2);
                            if (target7 != null) {
                                widget2.immediateConnect(ConstraintAnchor.Type.RIGHT, target7, ConstraintAnchor.Type.LEFT, layoutParams.rightMargin, resolveGoneRightMargin);
                            }
                        } else if (!(resolvedRightToRight == -1 || (target3 = getTargetWidget(resolvedRightToRight)) == null)) {
                            widget2.immediateConnect(ConstraintAnchor.Type.RIGHT, target3, ConstraintAnchor.Type.RIGHT, layoutParams.rightMargin, resolveGoneRightMargin);
                        }
                        if (layoutParams.topToTop != -1) {
                            ConstraintWidget target8 = getTargetWidget(layoutParams.topToTop);
                            if (target8 != null) {
                                widget2.immediateConnect(ConstraintAnchor.Type.TOP, target8, ConstraintAnchor.Type.TOP, layoutParams.topMargin, layoutParams.goneTopMargin);
                            }
                        } else if (!(layoutParams.topToBottom == -1 || (target2 = getTargetWidget(layoutParams.topToBottom)) == null)) {
                            widget2.immediateConnect(ConstraintAnchor.Type.TOP, target2, ConstraintAnchor.Type.BOTTOM, layoutParams.topMargin, layoutParams.goneTopMargin);
                        }
                        if (layoutParams.bottomToTop != -1) {
                            ConstraintWidget target9 = getTargetWidget(layoutParams.bottomToTop);
                            if (target9 != null) {
                                widget2.immediateConnect(ConstraintAnchor.Type.BOTTOM, target9, ConstraintAnchor.Type.TOP, layoutParams.bottomMargin, layoutParams.goneBottomMargin);
                            }
                        } else if (!(layoutParams.bottomToBottom == -1 || (target = getTargetWidget(layoutParams.bottomToBottom)) == null)) {
                            widget2.immediateConnect(ConstraintAnchor.Type.BOTTOM, target, ConstraintAnchor.Type.BOTTOM, layoutParams.bottomMargin, layoutParams.goneBottomMargin);
                        }
                        if (layoutParams.baselineToBaseline != -1) {
                            View view2 = ((ConstraintLayout) this).mChildrenByIds.get(layoutParams.baselineToBaseline);
                            ConstraintWidget target10 = getTargetWidget(layoutParams.baselineToBaseline);
                            if (!(target10 == null || view2 == null || !(view2.getLayoutParams() instanceof LayoutParams))) {
                                layoutParams.needsBaseline = USE_CONSTRAINTS_HELPER;
                                ((LayoutParams) view2.getLayoutParams()).needsBaseline = USE_CONSTRAINTS_HELPER;
                                widget2.getAnchor(ConstraintAnchor.Type.BASELINE).connect(target10.getAnchor(ConstraintAnchor.Type.BASELINE), 0, -1, ConstraintAnchor.Strength.STRONG, 0, USE_CONSTRAINTS_HELPER);
                                widget2.getAnchor(ConstraintAnchor.Type.TOP).reset();
                                widget2.getAnchor(ConstraintAnchor.Type.BOTTOM).reset();
                            }
                        }
                        if (resolvedHorizontalBias >= 0.0f && resolvedHorizontalBias != 0.5f) {
                            widget2.setHorizontalBiasPercent(resolvedHorizontalBias);
                        }
                        if (layoutParams.verticalBias >= 0.0f && layoutParams.verticalBias != 0.5f) {
                            widget2.setVerticalBiasPercent(layoutParams.verticalBias);
                        }
                    }
                    if (isInEditMode && !(layoutParams.editorAbsoluteX == -1 && layoutParams.editorAbsoluteY == -1)) {
                        widget2.setOrigin(layoutParams.editorAbsoluteX, layoutParams.editorAbsoluteY);
                    }
                    if (layoutParams.horizontalDimensionFixed) {
                        widget2.setHorizontalDimensionBehaviour(ConstraintWidget.DimensionBehaviour.FIXED);
                        widget2.setWidth(layoutParams.width);
                    } else if (layoutParams.width == -1) {
                        widget2.setHorizontalDimensionBehaviour(ConstraintWidget.DimensionBehaviour.MATCH_PARENT);
                        widget2.getAnchor(ConstraintAnchor.Type.LEFT).mMargin = layoutParams.leftMargin;
                        widget2.getAnchor(ConstraintAnchor.Type.RIGHT).mMargin = layoutParams.rightMargin;
                    } else {
                        widget2.setHorizontalDimensionBehaviour(ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT);
                        widget2.setWidth(0);
                    }
                    if (!layoutParams.verticalDimensionFixed) {
                        i = -1;
                        if (layoutParams.height == -1) {
                            widget2.setVerticalDimensionBehaviour(ConstraintWidget.DimensionBehaviour.MATCH_PARENT);
                            widget2.getAnchor(ConstraintAnchor.Type.TOP).mMargin = layoutParams.topMargin;
                            widget2.getAnchor(ConstraintAnchor.Type.BOTTOM).mMargin = layoutParams.bottomMargin;
                            z = false;
                        } else {
                            widget2.setVerticalDimensionBehaviour(ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT);
                            z = false;
                            widget2.setHeight(0);
                        }
                    } else {
                        z = false;
                        i = -1;
                        widget2.setVerticalDimensionBehaviour(ConstraintWidget.DimensionBehaviour.FIXED);
                        widget2.setHeight(layoutParams.height);
                    }
                    if (layoutParams.dimensionRatio != null) {
                        widget2.setDimensionRatio(layoutParams.dimensionRatio);
                    }
                    widget2.setHorizontalWeight(layoutParams.horizontalWeight);
                    widget2.setVerticalWeight(layoutParams.verticalWeight);
                    widget2.setHorizontalChainStyle(layoutParams.horizontalChainStyle);
                    widget2.setVerticalChainStyle(layoutParams.verticalChainStyle);
                    widget2.setHorizontalMatchStyle(layoutParams.matchConstraintDefaultWidth, layoutParams.matchConstraintMinWidth, layoutParams.matchConstraintMaxWidth, layoutParams.matchConstraintPercentWidth);
                    widget2.setVerticalMatchStyle(layoutParams.matchConstraintDefaultHeight, layoutParams.matchConstraintMinHeight, layoutParams.matchConstraintMaxHeight, layoutParams.matchConstraintPercentHeight);
                }
                count = count2;
                i = i3;
                helperCount = helperCount3;
                z = false;
            }
            i9++;
            z2 = z;
            i3 = i;
            count2 = count;
            helperCount3 = helperCount;
        }
    }

    private final ConstraintWidget getTargetWidget(int id) {
        if (id == 0) {
            return this.mLayoutWidget;
        }
        View view = this.mChildrenByIds.get(id);
        if (view == null && (view = findViewById(id)) != null && view != this && view.getParent() == this) {
            onViewAdded(view);
        }
        if (view == this) {
            return this.mLayoutWidget;
        }
        if (view == null) {
            return null;
        }
        return ((LayoutParams) view.getLayoutParams()).widget;
    }

    public final ConstraintWidget getViewWidget(View view) {
        if (view == this) {
            return this.mLayoutWidget;
        }
        if (view == null) {
            return null;
        }
        return ((LayoutParams) view.getLayoutParams()).widget;
    }

    private void internalMeasureChildren(int parentWidthSpec, int parentHeightSpec) {
        int baseline;
        int childWidthMeasureSpec;
        int childHeightMeasureSpec;
        ConstraintLayout constraintLayout = this;
        int i = parentWidthSpec;
        int heightPadding = getPaddingTop() + getPaddingBottom();
        int widthPadding = getPaddingLeft() + getPaddingRight();
        int widgetsCount = getChildCount();
        int i2 = 0;
        while (i2 < widgetsCount) {
            View child = constraintLayout.getChildAt(i2);
            if (child.getVisibility() != 8) {
                LayoutParams params = (LayoutParams) child.getLayoutParams();
                ConstraintWidget widget = params.widget;
                if (!params.isGuideline && !params.isHelper) {
                    widget.setVisibility(child.getVisibility());
                    int width = params.width;
                    int height = params.height;
                    boolean didWrapMeasureWidth = false;
                    boolean didWrapMeasureHeight = false;
                    if (params.horizontalDimensionFixed || params.verticalDimensionFixed || (!params.horizontalDimensionFixed && params.matchConstraintDefaultWidth == 1) || params.width == -1 || (!params.verticalDimensionFixed && (params.matchConstraintDefaultHeight == 1 || params.height == -1))) {
                        if (width == 0) {
                            childWidthMeasureSpec = getChildMeasureSpec(i, widthPadding, -2);
                            didWrapMeasureWidth = USE_CONSTRAINTS_HELPER;
                        } else if (width == -1) {
                            childWidthMeasureSpec = getChildMeasureSpec(i, widthPadding, -1);
                        } else {
                            if (width == -2) {
                                didWrapMeasureWidth = USE_CONSTRAINTS_HELPER;
                            }
                            childWidthMeasureSpec = getChildMeasureSpec(i, widthPadding, width);
                        }
                        if (height == 0) {
                            childHeightMeasureSpec = getChildMeasureSpec(parentHeightSpec, heightPadding, -2);
                            didWrapMeasureHeight = USE_CONSTRAINTS_HELPER;
                        } else if (height == -1) {
                            childHeightMeasureSpec = getChildMeasureSpec(parentHeightSpec, heightPadding, -1);
                        } else {
                            if (height == -2) {
                                didWrapMeasureHeight = USE_CONSTRAINTS_HELPER;
                            }
                            childHeightMeasureSpec = getChildMeasureSpec(parentHeightSpec, heightPadding, height);
                        }
                        child.measure(childWidthMeasureSpec, childHeightMeasureSpec);
                        if (constraintLayout.mMetrics != null) {
                            constraintLayout.mMetrics.measures++;
                        }
                        widget.setWidthWrapContent(width == -2 ? USE_CONSTRAINTS_HELPER : false);
                        widget.setHeightWrapContent(height == -2 ? USE_CONSTRAINTS_HELPER : false);
                        width = child.getMeasuredWidth();
                        height = child.getMeasuredHeight();
                    }
                    widget.setWidth(width);
                    widget.setHeight(height);
                    if (didWrapMeasureWidth) {
                        widget.setWrapWidth(width);
                    }
                    if (didWrapMeasureHeight) {
                        widget.setWrapHeight(height);
                    }
                    if (params.needsBaseline && (baseline = child.getBaseline()) != -1) {
                        widget.setBaselineDistance(baseline);
                    }
                }
            }
            i2++;
            constraintLayout = this;
            i = parentWidthSpec;
        }
    }

    private void updatePostMeasures() {
        int widgetsCount = getChildCount();
        for (int i = 0; i < widgetsCount; i++) {
            View child = getChildAt(i);
            if (child instanceof Placeholder) {
                ((Placeholder) child).updatePostMeasure(this);
            }
        }
        int helperCount = this.mConstraintHelpers.size();
        if (helperCount > 0) {
            for (int i2 = 0; i2 < helperCount; i2++) {
                this.mConstraintHelpers.get(i2).updatePostMeasure(this);
            }
        }
    }

    /* JADX INFO: Multiple debug info for r4v15 'heightPadding'  int: [D('widthPadding' int), D('heightPadding' int)] */
    /* JADX INFO: Multiple debug info for r4v17 'heightPadding'  int: [D('heightPadding' int), D('widthPadding' int)] */
    /* JADX WARNING: Removed duplicated region for block: B:112:0x0219  */
    /* JADX WARNING: Removed duplicated region for block: B:123:0x025f  */
    /* JADX WARNING: Removed duplicated region for block: B:132:0x0282  */
    /* JADX WARNING: Removed duplicated region for block: B:133:0x0291  */
    /* JADX WARNING: Removed duplicated region for block: B:136:0x029a  */
    /* JADX WARNING: Removed duplicated region for block: B:137:0x029c  */
    /* JADX WARNING: Removed duplicated region for block: B:140:0x02a2  */
    /* JADX WARNING: Removed duplicated region for block: B:141:0x02a4  */
    /* JADX WARNING: Removed duplicated region for block: B:144:0x02b8  */
    /* JADX WARNING: Removed duplicated region for block: B:146:0x02bd  */
    /* JADX WARNING: Removed duplicated region for block: B:148:0x02c2  */
    /* JADX WARNING: Removed duplicated region for block: B:149:0x02ca  */
    /* JADX WARNING: Removed duplicated region for block: B:151:0x02d3  */
    /* JADX WARNING: Removed duplicated region for block: B:152:0x02db  */
    /* JADX WARNING: Removed duplicated region for block: B:155:0x02e8  */
    /* JADX WARNING: Removed duplicated region for block: B:158:0x02f3  */
    private void internalMeasureDimensions(int parentWidthSpec, int parentHeightSpec) {
        int i;
        int heightPadding;
        int widthPadding;
        int i2;
        int widgetsCount;
        int childWidthMeasureSpec;
        boolean resolveHeight;
        int childHeightMeasureSpec;
        int widthPadding2;
        int i3;
        int heightPadding2;
        int heightPadding3;
        int baseline;
        int i4 = parentWidthSpec;
        int i5 = parentHeightSpec;
        int heightPadding4 = getPaddingTop() + getPaddingBottom();
        int widthPadding3 = getPaddingLeft() + getPaddingRight();
        int widgetsCount2 = getChildCount();
        int i6 = 0;
        while (true) {
            i = 8;
            if (i6 >= widgetsCount2) {
                break;
            }
            View child = getChildAt(i6);
            if (child.getVisibility() != 8) {
                LayoutParams params = (LayoutParams) child.getLayoutParams();
                ConstraintWidget widget = params.widget;
                if (params.isGuideline) {
                    heightPadding2 = heightPadding4;
                } else if (!params.isHelper) {
                    widget.setVisibility(child.getVisibility());
                    int width = params.width;
                    int height = params.height;
                    if (width == 0) {
                        heightPadding3 = heightPadding4;
                    } else if (height == 0) {
                        heightPadding3 = heightPadding4;
                    } else {
                        boolean didWrapMeasureWidth = false;
                        boolean didWrapMeasureHeight = false;
                        if (width == -2) {
                            didWrapMeasureWidth = USE_CONSTRAINTS_HELPER;
                        }
                        int childWidthMeasureSpec2 = getChildMeasureSpec(i4, widthPadding3, width);
                        if (height == -2) {
                            didWrapMeasureHeight = USE_CONSTRAINTS_HELPER;
                        }
                        child.measure(childWidthMeasureSpec2, getChildMeasureSpec(i5, heightPadding4, height));
                        if (this.mMetrics != null) {
                            heightPadding2 = heightPadding4;
                            this.mMetrics.measures++;
                        } else {
                            heightPadding2 = heightPadding4;
                        }
                        widget.setWidthWrapContent(width == -2 ? USE_CONSTRAINTS_HELPER : false);
                        widget.setHeightWrapContent(height == -2 ? USE_CONSTRAINTS_HELPER : false);
                        int width2 = child.getMeasuredWidth();
                        int height2 = child.getMeasuredHeight();
                        widget.setWidth(width2);
                        widget.setHeight(height2);
                        if (didWrapMeasureWidth) {
                            widget.setWrapWidth(width2);
                        }
                        if (didWrapMeasureHeight) {
                            widget.setWrapHeight(height2);
                        }
                        if (params.needsBaseline && (baseline = child.getBaseline()) != -1) {
                            widget.setBaselineDistance(baseline);
                        }
                        if (params.horizontalDimensionFixed != 0 && params.verticalDimensionFixed) {
                            widget.getResolutionWidth().resolve(width2);
                            widget.getResolutionHeight().resolve(height2);
                        }
                    }
                    widget.getResolutionWidth().invalidate();
                    widget.getResolutionHeight().invalidate();
                }
                i6++;
                heightPadding4 = heightPadding2;
                i5 = parentHeightSpec;
            }
            heightPadding2 = heightPadding4;
            i6++;
            heightPadding4 = heightPadding2;
            i5 = parentHeightSpec;
        }
        int heightPadding5 = heightPadding4;
        this.mLayoutWidget.solveGraph();
        int i7 = 0;
        while (i7 < widgetsCount2) {
            View child2 = getChildAt(i7);
            if (child2.getVisibility() != i) {
                LayoutParams params2 = (LayoutParams) child2.getLayoutParams();
                ConstraintWidget widget2 = params2.widget;
                if (params2.isGuideline) {
                    i2 = i7;
                    widthPadding = widthPadding3;
                    widgetsCount = widgetsCount2;
                    heightPadding = heightPadding5;
                } else if (!params2.isHelper) {
                    widget2.setVisibility(child2.getVisibility());
                    int width3 = params2.width;
                    int height3 = params2.height;
                    if (width3 == 0 || height3 == 0) {
                        ResolutionAnchor left = widget2.getAnchor(ConstraintAnchor.Type.LEFT).getResolutionNode();
                        ResolutionAnchor right = widget2.getAnchor(ConstraintAnchor.Type.RIGHT).getResolutionNode();
                        boolean bothHorizontal = (widget2.getAnchor(ConstraintAnchor.Type.LEFT).getTarget() == null || widget2.getAnchor(ConstraintAnchor.Type.RIGHT).getTarget() == null) ? false : USE_CONSTRAINTS_HELPER;
                        ResolutionAnchor top = widget2.getAnchor(ConstraintAnchor.Type.TOP).getResolutionNode();
                        ResolutionAnchor bottom = widget2.getAnchor(ConstraintAnchor.Type.BOTTOM).getResolutionNode();
                        boolean bothVertical = (widget2.getAnchor(ConstraintAnchor.Type.TOP).getTarget() == null || widget2.getAnchor(ConstraintAnchor.Type.BOTTOM).getTarget() == null) ? false : USE_CONSTRAINTS_HELPER;
                        if (width3 != 0 || height3 != 0 || !bothHorizontal || !bothVertical) {
                            boolean didWrapMeasureWidth2 = false;
                            boolean didWrapMeasureHeight2 = false;
                            widgetsCount = widgetsCount2;
                            i2 = i7;
                            boolean resolveWidth = this.mLayoutWidget.getHorizontalDimensionBehaviour() != ConstraintWidget.DimensionBehaviour.WRAP_CONTENT ? USE_CONSTRAINTS_HELPER : false;
                            boolean resolveHeight2 = this.mLayoutWidget.getVerticalDimensionBehaviour() != ConstraintWidget.DimensionBehaviour.WRAP_CONTENT ? USE_CONSTRAINTS_HELPER : false;
                            if (!resolveWidth) {
                                widget2.getResolutionWidth().invalidate();
                            }
                            if (!resolveHeight2) {
                                widget2.getResolutionHeight().invalidate();
                            }
                            if (width3 == 0) {
                                if (!resolveWidth || !widget2.isSpreadWidth() || !bothHorizontal || !left.isResolved() || !right.isResolved()) {
                                    childWidthMeasureSpec = getChildMeasureSpec(i4, widthPadding3, -2);
                                    didWrapMeasureWidth2 = USE_CONSTRAINTS_HELPER;
                                    resolveWidth = false;
                                    if (height3 == 0) {
                                        if (!resolveHeight2 || !widget2.isSpreadHeight() || !bothVertical || !top.isResolved() || !bottom.isResolved()) {
                                            widthPadding = widthPadding3;
                                            widthPadding2 = heightPadding5;
                                            childHeightMeasureSpec = getChildMeasureSpec(parentHeightSpec, widthPadding2, -2);
                                            didWrapMeasureHeight2 = USE_CONSTRAINTS_HELPER;
                                            resolveHeight2 = false;
                                        } else {
                                            height3 = (int) (bottom.getResolvedValue() - top.getResolvedValue());
                                            widget2.getResolutionHeight().resolve(height3);
                                            widthPadding = widthPadding3;
                                            widthPadding2 = heightPadding5;
                                            childHeightMeasureSpec = getChildMeasureSpec(parentHeightSpec, widthPadding2, height3);
                                        }
                                        resolveHeight = resolveHeight2;
                                    } else {
                                        widthPadding = widthPadding3;
                                        resolveHeight = resolveHeight2;
                                        widthPadding2 = heightPadding5;
                                        if (height3 == -1) {
                                            childHeightMeasureSpec = getChildMeasureSpec(parentHeightSpec, widthPadding2, -1);
                                        } else {
                                            if (height3 == -2) {
                                                didWrapMeasureHeight2 = true;
                                            }
                                            childHeightMeasureSpec = getChildMeasureSpec(parentHeightSpec, widthPadding2, height3);
                                        }
                                    }
                                    child2.measure(childWidthMeasureSpec, childHeightMeasureSpec);
                                    if (this.mMetrics != null) {
                                        heightPadding = widthPadding2;
                                        this.mMetrics.measures++;
                                    } else {
                                        heightPadding = widthPadding2;
                                    }
                                    widget2.setWidthWrapContent(width3 == -2 ? USE_CONSTRAINTS_HELPER : false);
                                    widget2.setHeightWrapContent(height3 == -2 ? USE_CONSTRAINTS_HELPER : false);
                                    int width4 = child2.getMeasuredWidth();
                                    int height4 = child2.getMeasuredHeight();
                                    widget2.setWidth(width4);
                                    widget2.setHeight(height4);
                                    if (didWrapMeasureWidth2) {
                                        widget2.setWrapWidth(width4);
                                    }
                                    if (didWrapMeasureHeight2) {
                                        widget2.setWrapHeight(height4);
                                    }
                                    if (resolveWidth) {
                                        widget2.getResolutionWidth().resolve(width4);
                                    } else {
                                        widget2.getResolutionWidth().remove();
                                    }
                                    if (resolveHeight) {
                                        widget2.getResolutionHeight().resolve(height4);
                                    } else {
                                        widget2.getResolutionHeight().remove();
                                    }
                                    if (params2.needsBaseline) {
                                        int baseline2 = child2.getBaseline();
                                        if (baseline2 != -1) {
                                            widget2.setBaselineDistance(baseline2);
                                        }
                                    }
                                } else {
                                    width3 = (int) (right.getResolvedValue() - left.getResolvedValue());
                                    widget2.getResolutionWidth().resolve(width3);
                                    i3 = getChildMeasureSpec(i4, widthPadding3, width3);
                                }
                            } else if (width3 == -1) {
                                childWidthMeasureSpec = getChildMeasureSpec(i4, widthPadding3, -1);
                                if (height3 == 0) {
                                }
                                child2.measure(childWidthMeasureSpec, childHeightMeasureSpec);
                                if (this.mMetrics != null) {
                                }
                                widget2.setWidthWrapContent(width3 == -2 ? USE_CONSTRAINTS_HELPER : false);
                                widget2.setHeightWrapContent(height3 == -2 ? USE_CONSTRAINTS_HELPER : false);
                                int width42 = child2.getMeasuredWidth();
                                int height42 = child2.getMeasuredHeight();
                                widget2.setWidth(width42);
                                widget2.setHeight(height42);
                                if (didWrapMeasureWidth2) {
                                }
                                if (didWrapMeasureHeight2) {
                                }
                                if (resolveWidth) {
                                }
                                if (resolveHeight) {
                                }
                                if (params2.needsBaseline) {
                                }
                            } else {
                                if (width3 == -2) {
                                    didWrapMeasureWidth2 = true;
                                }
                                i3 = getChildMeasureSpec(i4, widthPadding3, width3);
                            }
                            childWidthMeasureSpec = i3;
                            if (height3 == 0) {
                            }
                            child2.measure(childWidthMeasureSpec, childHeightMeasureSpec);
                            if (this.mMetrics != null) {
                            }
                            widget2.setWidthWrapContent(width3 == -2 ? USE_CONSTRAINTS_HELPER : false);
                            widget2.setHeightWrapContent(height3 == -2 ? USE_CONSTRAINTS_HELPER : false);
                            int width422 = child2.getMeasuredWidth();
                            int height422 = child2.getMeasuredHeight();
                            widget2.setWidth(width422);
                            widget2.setHeight(height422);
                            if (didWrapMeasureWidth2) {
                            }
                            if (didWrapMeasureHeight2) {
                            }
                            if (resolveWidth) {
                            }
                            if (resolveHeight) {
                            }
                            if (params2.needsBaseline) {
                            }
                        }
                    }
                }
                i7 = i2 + 1;
                widgetsCount2 = widgetsCount;
                widthPadding3 = widthPadding;
                heightPadding5 = heightPadding;
                i4 = parentWidthSpec;
                i = 8;
            }
            i2 = i7;
            widthPadding = widthPadding3;
            widgetsCount = widgetsCount2;
            heightPadding = heightPadding5;
            i7 = i2 + 1;
            widgetsCount2 = widgetsCount;
            widthPadding3 = widthPadding;
            heightPadding5 = heightPadding;
            i4 = parentWidthSpec;
            i = 8;
        }
    }

    public void fillMetrics(Metrics metrics) {
        this.mMetrics = metrics;
        this.mLayoutWidget.fillMetrics(metrics);
    }

    /* JADX INFO: Multiple debug info for r5v8 android.view.View: [D('sizeDependentWidgetsCount' int), D('child' android.view.View)] */
    /* JADX INFO: Multiple debug info for r14v14 android.support.constraint.ConstraintLayout$LayoutParams: [D('startingHeight' int), D('params' android.support.constraint.ConstraintLayout$LayoutParams)] */
    /* JADX INFO: Multiple debug info for r1v28 int: [D('minHeight' int), D('h' int)] */
    /* access modifiers changed from: protected */
    public void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int REMEASURES_B;
        int childState;
        int startingWidth;
        boolean containerWrapWidth;
        int startingWidth2;
        int i;
        int startingWidth3;
        int startingHeight;
        int widthSpec;
        int heightSpec;
        int baseline;
        int i2 = widthMeasureSpec;
        int i3 = heightMeasureSpec;
        System.currentTimeMillis();
        int widthMode = View.MeasureSpec.getMode(widthMeasureSpec);
        int widthSize = View.MeasureSpec.getSize(widthMeasureSpec);
        int heightMode = View.MeasureSpec.getMode(heightMeasureSpec);
        int heightSize = View.MeasureSpec.getSize(heightMeasureSpec);
        int paddingLeft = getPaddingLeft();
        int paddingTop = getPaddingTop();
        this.mLayoutWidget.setX(paddingLeft);
        this.mLayoutWidget.setY(paddingTop);
        this.mLayoutWidget.setMaxWidth(this.mMaxWidth);
        this.mLayoutWidget.setMaxHeight(this.mMaxHeight);
        if (Build.VERSION.SDK_INT >= 17) {
            this.mLayoutWidget.setRtl(getLayoutDirection() == 1);
        }
        setSelfDimensionBehaviour(widthMeasureSpec, heightMeasureSpec);
        int startingWidth4 = this.mLayoutWidget.getWidth();
        int startingHeight2 = this.mLayoutWidget.getHeight();
        boolean runAnalyzer = false;
        if (this.mDirtyHierarchy) {
            this.mDirtyHierarchy = false;
            updateHierarchy();
            runAnalyzer = USE_CONSTRAINTS_HELPER;
        }
        boolean optimiseDimensions = (this.mOptimizationLevel & 8) == 8 ? USE_CONSTRAINTS_HELPER : false;
        if (optimiseDimensions) {
            this.mLayoutWidget.preOptimize();
            this.mLayoutWidget.optimizeForDimensions(startingWidth4, startingHeight2);
            internalMeasureDimensions(widthMeasureSpec, heightMeasureSpec);
        } else {
            internalMeasureChildren(widthMeasureSpec, heightMeasureSpec);
        }
        updatePostMeasures();
        if (getChildCount() > 0 && runAnalyzer) {
            Analyzer.determineGroups(this.mLayoutWidget);
        }
        if (this.mLayoutWidget.mGroupsWrapOptimized) {
            if (this.mLayoutWidget.mHorizontalWrapOptimized && widthMode == Integer.MIN_VALUE) {
                if (this.mLayoutWidget.mWrapFixedWidth < widthSize) {
                    this.mLayoutWidget.setWidth(this.mLayoutWidget.mWrapFixedWidth);
                }
                this.mLayoutWidget.setHorizontalDimensionBehaviour(ConstraintWidget.DimensionBehaviour.FIXED);
            }
            if (this.mLayoutWidget.mVerticalWrapOptimized && heightMode == Integer.MIN_VALUE) {
                if (this.mLayoutWidget.mWrapFixedHeight < heightSize) {
                    this.mLayoutWidget.setHeight(this.mLayoutWidget.mWrapFixedHeight);
                }
                this.mLayoutWidget.setVerticalDimensionBehaviour(ConstraintWidget.DimensionBehaviour.FIXED);
            }
        }
        int REMEASURES_A = 0;
        if ((this.mOptimizationLevel & 32) == 32) {
            int width = this.mLayoutWidget.getWidth();
            int height = this.mLayoutWidget.getHeight();
            if (this.mLastMeasureWidth == width || widthMode != 1073741824) {
                REMEASURES_B = 0;
            } else {
                REMEASURES_B = 0;
                Analyzer.setPosition(this.mLayoutWidget.mWidgetGroups, 0, width);
            }
            if (this.mLastMeasureHeight != height && heightMode == 1073741824) {
                Analyzer.setPosition(this.mLayoutWidget.mWidgetGroups, 1, height);
            }
            if (this.mLayoutWidget.mHorizontalWrapOptimized && this.mLayoutWidget.mWrapFixedWidth > widthSize) {
                Analyzer.setPosition(this.mLayoutWidget.mWidgetGroups, 0, widthSize);
            }
            if (this.mLayoutWidget.mVerticalWrapOptimized && this.mLayoutWidget.mWrapFixedHeight > heightSize) {
                Analyzer.setPosition(this.mLayoutWidget.mWidgetGroups, 1, heightSize);
            }
        } else {
            REMEASURES_B = 0;
        }
        if (getChildCount() > 0) {
            solveLinearSystem("First pass");
        }
        int sizeDependentWidgetsCount = this.mVariableDimensionsWidgets.size();
        int heightPadding = getPaddingBottom() + paddingTop;
        int widthPadding = paddingLeft + getPaddingRight();
        if (sizeDependentWidgetsCount > 0) {
            boolean needSolverPass = false;
            boolean containerWrapWidth2 = this.mLayoutWidget.getHorizontalDimensionBehaviour() == ConstraintWidget.DimensionBehaviour.WRAP_CONTENT ? USE_CONSTRAINTS_HELPER : false;
            boolean containerWrapHeight = this.mLayoutWidget.getVerticalDimensionBehaviour() == ConstraintWidget.DimensionBehaviour.WRAP_CONTENT ? USE_CONSTRAINTS_HELPER : false;
            childState = 0;
            int minWidth = Math.max(this.mLayoutWidget.getWidth(), this.mMinWidth);
            int minHeight = Math.max(this.mLayoutWidget.getHeight(), this.mMinHeight);
            int i4 = 0;
            while (i4 < sizeDependentWidgetsCount) {
                ConstraintWidget widget = this.mVariableDimensionsWidgets.get(i4);
                View child = (View) widget.getCompanionWidget();
                if (child == null) {
                    i = i4;
                    startingWidth3 = startingWidth4;
                    startingHeight = startingHeight2;
                } else {
                    startingHeight = startingHeight2;
                    LayoutParams params = (LayoutParams) child.getLayoutParams();
                    startingWidth3 = startingWidth4;
                    if (params.isHelper != 0) {
                        i = i4;
                    } else if (params.isGuideline) {
                        i = i4;
                    } else {
                        i = i4;
                        if (child.getVisibility() != 8 && (!optimiseDimensions || !widget.getResolutionWidth().isResolved() || !widget.getResolutionHeight().isResolved())) {
                            if (params.width != -2 || !params.horizontalDimensionFixed) {
                                widthSpec = View.MeasureSpec.makeMeasureSpec(widget.getWidth(), 1073741824);
                            } else {
                                widthSpec = getChildMeasureSpec(i2, widthPadding, params.width);
                            }
                            if (params.height != -2 || !params.verticalDimensionFixed) {
                                heightSpec = View.MeasureSpec.makeMeasureSpec(widget.getHeight(), 1073741824);
                            } else {
                                heightSpec = getChildMeasureSpec(i3, heightPadding, params.height);
                            }
                            child.measure(widthSpec, heightSpec);
                            if (this.mMetrics != null) {
                                this.mMetrics.additionalMeasures++;
                            }
                            REMEASURES_A++;
                            int measuredWidth = child.getMeasuredWidth();
                            int measuredHeight = child.getMeasuredHeight();
                            if (measuredWidth != widget.getWidth()) {
                                widget.setWidth(measuredWidth);
                                if (optimiseDimensions) {
                                    widget.getResolutionWidth().resolve(measuredWidth);
                                }
                                if (containerWrapWidth2 && widget.getRight() > minWidth) {
                                    minWidth = Math.max(minWidth, widget.getRight() + widget.getAnchor(ConstraintAnchor.Type.RIGHT).getMargin());
                                }
                                needSolverPass = USE_CONSTRAINTS_HELPER;
                            }
                            if (measuredHeight != widget.getHeight()) {
                                widget.setHeight(measuredHeight);
                                if (optimiseDimensions) {
                                    widget.getResolutionHeight().resolve(measuredHeight);
                                }
                                if (containerWrapHeight && widget.getBottom() > minHeight) {
                                    minHeight = Math.max(minHeight, widget.getBottom() + widget.getAnchor(ConstraintAnchor.Type.BOTTOM).getMargin());
                                }
                                needSolverPass = USE_CONSTRAINTS_HELPER;
                            }
                            if (!(!params.needsBaseline || (baseline = child.getBaseline()) == -1 || baseline == widget.getBaselineDistance())) {
                                widget.setBaselineDistance(baseline);
                                needSolverPass = USE_CONSTRAINTS_HELPER;
                            }
                            if (Build.VERSION.SDK_INT >= 11) {
                                childState = combineMeasuredStates(childState, child.getMeasuredState());
                            }
                        }
                    }
                }
                i4 = i + 1;
                paddingTop = paddingTop;
                sizeDependentWidgetsCount = sizeDependentWidgetsCount;
                startingHeight2 = startingHeight;
                startingWidth4 = startingWidth3;
                i2 = widthMeasureSpec;
                i3 = heightMeasureSpec;
            }
            int sizeDependentWidgetsCount2 = sizeDependentWidgetsCount;
            if (needSolverPass) {
                startingWidth = startingWidth4;
                this.mLayoutWidget.setWidth(startingWidth);
                this.mLayoutWidget.setHeight(startingHeight2);
                if (optimiseDimensions) {
                    this.mLayoutWidget.solveGraph();
                }
                solveLinearSystem("2nd pass");
                boolean needSolverPass2 = false;
                if (this.mLayoutWidget.getWidth() < minWidth) {
                    this.mLayoutWidget.setWidth(minWidth);
                    needSolverPass2 = USE_CONSTRAINTS_HELPER;
                }
                if (this.mLayoutWidget.getHeight() < minHeight) {
                    this.mLayoutWidget.setHeight(minHeight);
                    needSolverPass2 = USE_CONSTRAINTS_HELPER;
                }
                if (needSolverPass2) {
                    solveLinearSystem("3rd pass");
                }
            } else {
                startingWidth = startingWidth4;
            }
            int i5 = 0;
            while (i5 < sizeDependentWidgetsCount2) {
                ConstraintWidget widget2 = this.mVariableDimensionsWidgets.get(i5);
                View child2 = (View) widget2.getCompanionWidget();
                if (child2 == null) {
                    startingWidth2 = startingWidth;
                } else {
                    startingWidth2 = startingWidth;
                    if (!(child2.getMeasuredWidth() == widget2.getWidth() && child2.getMeasuredHeight() == widget2.getHeight())) {
                        if (widget2.getVisibility() != 8) {
                            containerWrapWidth = containerWrapWidth2;
                            child2.measure(View.MeasureSpec.makeMeasureSpec(widget2.getWidth(), 1073741824), View.MeasureSpec.makeMeasureSpec(widget2.getHeight(), 1073741824));
                            if (this.mMetrics != null) {
                                this.mMetrics.additionalMeasures++;
                            }
                            REMEASURES_B++;
                        } else {
                            containerWrapWidth = containerWrapWidth2;
                        }
                        i5++;
                        sizeDependentWidgetsCount2 = sizeDependentWidgetsCount2;
                        startingWidth = startingWidth2;
                        containerWrapWidth2 = containerWrapWidth;
                    }
                }
                containerWrapWidth = containerWrapWidth2;
                i5++;
                sizeDependentWidgetsCount2 = sizeDependentWidgetsCount2;
                startingWidth = startingWidth2;
                containerWrapWidth2 = containerWrapWidth;
            }
        } else {
            childState = 0;
        }
        int androidLayoutWidth = this.mLayoutWidget.getWidth() + widthPadding;
        int androidLayoutHeight = this.mLayoutWidget.getHeight() + heightPadding;
        if (Build.VERSION.SDK_INT >= 11) {
            int resolvedWidthSize = Math.min(this.mMaxWidth, resolveSizeAndState(androidLayoutWidth, widthMeasureSpec, childState) & 16777215);
            int resolvedHeightSize = Math.min(this.mMaxHeight, resolveSizeAndState(androidLayoutHeight, heightMeasureSpec, childState << 16) & 16777215);
            if (this.mLayoutWidget.isWidthMeasuredTooSmall()) {
                resolvedWidthSize |= 16777216;
            }
            if (this.mLayoutWidget.isHeightMeasuredTooSmall()) {
                resolvedHeightSize |= 16777216;
            }
            setMeasuredDimension(resolvedWidthSize, resolvedHeightSize);
            this.mLastMeasureWidth = resolvedWidthSize;
            this.mLastMeasureHeight = resolvedHeightSize;
            return;
        }
        setMeasuredDimension(androidLayoutWidth, androidLayoutHeight);
        this.mLastMeasureWidth = androidLayoutWidth;
        this.mLastMeasureHeight = androidLayoutHeight;
    }

    private void setSelfDimensionBehaviour(int widthMeasureSpec, int heightMeasureSpec) {
        int widthMode = View.MeasureSpec.getMode(widthMeasureSpec);
        int widthSize = View.MeasureSpec.getSize(widthMeasureSpec);
        int heightMode = View.MeasureSpec.getMode(heightMeasureSpec);
        int heightSize = View.MeasureSpec.getSize(heightMeasureSpec);
        int heightPadding = getPaddingTop() + getPaddingBottom();
        int widthPadding = getPaddingLeft() + getPaddingRight();
        ConstraintWidget.DimensionBehaviour widthBehaviour = ConstraintWidget.DimensionBehaviour.FIXED;
        ConstraintWidget.DimensionBehaviour heightBehaviour = ConstraintWidget.DimensionBehaviour.FIXED;
        int desiredWidth = 0;
        int desiredHeight = 0;
        getLayoutParams();
        if (widthMode == Integer.MIN_VALUE) {
            widthBehaviour = ConstraintWidget.DimensionBehaviour.WRAP_CONTENT;
            desiredWidth = widthSize;
        } else if (widthMode == 0) {
            widthBehaviour = ConstraintWidget.DimensionBehaviour.WRAP_CONTENT;
        } else if (widthMode == 1073741824) {
            desiredWidth = Math.min(this.mMaxWidth, widthSize) - widthPadding;
        }
        if (heightMode == Integer.MIN_VALUE) {
            heightBehaviour = ConstraintWidget.DimensionBehaviour.WRAP_CONTENT;
            desiredHeight = heightSize;
        } else if (heightMode == 0) {
            heightBehaviour = ConstraintWidget.DimensionBehaviour.WRAP_CONTENT;
        } else if (heightMode == 1073741824) {
            desiredHeight = Math.min(this.mMaxHeight, heightSize) - heightPadding;
        }
        this.mLayoutWidget.setMinWidth(0);
        this.mLayoutWidget.setMinHeight(0);
        this.mLayoutWidget.setHorizontalDimensionBehaviour(widthBehaviour);
        this.mLayoutWidget.setWidth(desiredWidth);
        this.mLayoutWidget.setVerticalDimensionBehaviour(heightBehaviour);
        this.mLayoutWidget.setHeight(desiredHeight);
        this.mLayoutWidget.setMinWidth((this.mMinWidth - getPaddingLeft()) - getPaddingRight());
        this.mLayoutWidget.setMinHeight((this.mMinHeight - getPaddingTop()) - getPaddingBottom());
    }

    /* access modifiers changed from: protected */
    public void solveLinearSystem(String reason) {
        this.mLayoutWidget.layout();
        if (this.mMetrics != null) {
            this.mMetrics.resolutions++;
        }
    }

    /* access modifiers changed from: protected */
    public void onLayout(boolean changed, int left, int top, int right, int bottom) {
        View content;
        int widgetsCount = getChildCount();
        boolean isInEditMode = isInEditMode();
        for (int i = 0; i < widgetsCount; i++) {
            View child = getChildAt(i);
            LayoutParams params = (LayoutParams) child.getLayoutParams();
            ConstraintWidget widget = params.widget;
            if ((child.getVisibility() != 8 || params.isGuideline || params.isHelper || isInEditMode) && !params.isInPlaceholder) {
                int l = widget.getDrawX();
                int t = widget.getDrawY();
                int r = widget.getWidth() + l;
                int b = widget.getHeight() + t;
                child.layout(l, t, r, b);
                if ((child instanceof Placeholder) && (content = ((Placeholder) child).getContent()) != null) {
                    content.setVisibility(0);
                    content.layout(l, t, r, b);
                }
            }
        }
        int helperCount = this.mConstraintHelpers.size();
        if (helperCount > 0) {
            for (int i2 = 0; i2 < helperCount; i2++) {
                this.mConstraintHelpers.get(i2).updatePostLayout(this);
            }
        }
    }

    public void setOptimizationLevel(int level) {
        this.mLayoutWidget.setOptimizationLevel(level);
    }

    public int getOptimizationLevel() {
        return this.mLayoutWidget.getOptimizationLevel();
    }

    @Override // android.view.ViewGroup
    public LayoutParams generateLayoutParams(AttributeSet attrs) {
        return new LayoutParams(getContext(), attrs);
    }

    /* access modifiers changed from: protected */
    public LayoutParams generateDefaultLayoutParams() {
        return new LayoutParams(-2, -2);
    }

    /* access modifiers changed from: protected */
    @Override // android.view.ViewGroup
    public ViewGroup.LayoutParams generateLayoutParams(ViewGroup.LayoutParams p) {
        return new LayoutParams(p);
    }

    /* access modifiers changed from: protected */
    public boolean checkLayoutParams(ViewGroup.LayoutParams p) {
        return p instanceof LayoutParams;
    }

    public void setConstraintSet(ConstraintSet set) {
        this.mConstraintSet = set;
    }

    public View getViewById(int id) {
        return this.mChildrenByIds.get(id);
    }

    public void dispatchDraw(Canvas canvas) {
        float ow;
        float ch;
        float cw;
        int count;
        super.dispatchDraw(canvas);
        if (isInEditMode()) {
            int count2 = getChildCount();
            float cw2 = (float) getWidth();
            float ch2 = (float) getHeight();
            float ow2 = 1080.0f;
            char c = 0;
            int i = 0;
            while (i < count2) {
                View child = getChildAt(i);
                if (child.getVisibility() == 8) {
                    count = count2;
                    cw = cw2;
                    ch = ch2;
                    ow = ow2;
                } else {
                    Object tag = child.getTag();
                    if (tag != null && (tag instanceof String)) {
                        String[] split = ((String) tag).split(",");
                        if (split.length == 4) {
                            int x = Integer.parseInt(split[c]);
                            int x2 = (int) ((((float) x) / ow2) * cw2);
                            int y = (int) ((((float) Integer.parseInt(split[1])) / 1920.0f) * ch2);
                            int w = (int) ((((float) Integer.parseInt(split[2])) / ow2) * cw2);
                            int h = (int) ((((float) Integer.parseInt(split[3])) / 1920.0f) * ch2);
                            Paint paint = new Paint();
                            count = count2;
                            paint.setColor(-65536);
                            cw = cw2;
                            ch = ch2;
                            ow = ow2;
                            canvas.drawLine((float) x2, (float) y, (float) (x2 + w), (float) y, paint);
                            canvas.drawLine((float) (x2 + w), (float) y, (float) (x2 + w), (float) (y + h), paint);
                            canvas.drawLine((float) (x2 + w), (float) (y + h), (float) x2, (float) (y + h), paint);
                            canvas.drawLine((float) x2, (float) (y + h), (float) x2, (float) y, paint);
                            paint.setColor(-16711936);
                            canvas.drawLine((float) x2, (float) y, (float) (x2 + w), (float) (y + h), paint);
                            canvas.drawLine((float) x2, (float) (y + h), (float) (x2 + w), (float) y, paint);
                        }
                    }
                    count = count2;
                    cw = cw2;
                    ch = ch2;
                    ow = ow2;
                }
                i++;
                count2 = count;
                cw2 = cw;
                ch2 = ch;
                ow2 = ow;
                c = 0;
            }
        }
    }

    public static class LayoutParams extends ViewGroup.MarginLayoutParams {
        public static final int BASELINE = 5;
        public static final int BOTTOM = 4;
        public static final int CHAIN_PACKED = 2;
        public static final int CHAIN_SPREAD = 0;
        public static final int CHAIN_SPREAD_INSIDE = 1;
        public static final int END = 7;
        public static final int HORIZONTAL = 0;
        public static final int LEFT = 1;
        public static final int MATCH_CONSTRAINT = 0;
        public static final int MATCH_CONSTRAINT_PERCENT = 2;
        public static final int MATCH_CONSTRAINT_SPREAD = 0;
        public static final int MATCH_CONSTRAINT_WRAP = 1;
        public static final int PARENT_ID = 0;
        public static final int RIGHT = 2;
        public static final int START = 6;
        public static final int TOP = 3;
        public static final int UNSET = -1;
        public static final int VERTICAL = 1;
        public int baselineToBaseline;
        public int bottomToBottom;
        public int bottomToTop;
        public float circleAngle;
        public int circleConstraint;
        public int circleRadius;
        public boolean constrainedHeight;
        public boolean constrainedWidth;
        public String dimensionRatio;
        int dimensionRatioSide;
        float dimensionRatioValue;
        public int editorAbsoluteX;
        public int editorAbsoluteY;
        public int endToEnd;
        public int endToStart;
        public int goneBottomMargin;
        public int goneEndMargin;
        public int goneLeftMargin;
        public int goneRightMargin;
        public int goneStartMargin;
        public int goneTopMargin;
        public int guideBegin;
        public int guideEnd;
        public float guidePercent;
        public boolean helped;
        public float horizontalBias;
        public int horizontalChainStyle;
        boolean horizontalDimensionFixed;
        public float horizontalWeight;
        boolean isGuideline;
        boolean isHelper;
        boolean isInPlaceholder;
        public int leftToLeft;
        public int leftToRight;
        public int matchConstraintDefaultHeight;
        public int matchConstraintDefaultWidth;
        public int matchConstraintMaxHeight;
        public int matchConstraintMaxWidth;
        public int matchConstraintMinHeight;
        public int matchConstraintMinWidth;
        public float matchConstraintPercentHeight;
        public float matchConstraintPercentWidth;
        boolean needsBaseline;
        public int orientation;
        int resolveGoneLeftMargin;
        int resolveGoneRightMargin;
        int resolvedGuideBegin;
        int resolvedGuideEnd;
        float resolvedGuidePercent;
        float resolvedHorizontalBias;
        int resolvedLeftToLeft;
        int resolvedLeftToRight;
        int resolvedRightToLeft;
        int resolvedRightToRight;
        public int rightToLeft;
        public int rightToRight;
        public int startToEnd;
        public int startToStart;
        public int topToBottom;
        public int topToTop;
        public float verticalBias;
        public int verticalChainStyle;
        boolean verticalDimensionFixed;
        public float verticalWeight;
        ConstraintWidget widget;

        public void reset() {
            if (this.widget != null) {
                this.widget.reset();
            }
        }

        public LayoutParams(LayoutParams source) {
            super((ViewGroup.MarginLayoutParams) source);
            this.guideBegin = -1;
            this.guideEnd = -1;
            this.guidePercent = -1.0f;
            this.leftToLeft = -1;
            this.leftToRight = -1;
            this.rightToLeft = -1;
            this.rightToRight = -1;
            this.topToTop = -1;
            this.topToBottom = -1;
            this.bottomToTop = -1;
            this.bottomToBottom = -1;
            this.baselineToBaseline = -1;
            this.circleConstraint = -1;
            this.circleRadius = 0;
            this.circleAngle = 0.0f;
            this.startToEnd = -1;
            this.startToStart = -1;
            this.endToStart = -1;
            this.endToEnd = -1;
            this.goneLeftMargin = -1;
            this.goneTopMargin = -1;
            this.goneRightMargin = -1;
            this.goneBottomMargin = -1;
            this.goneStartMargin = -1;
            this.goneEndMargin = -1;
            this.horizontalBias = 0.5f;
            this.verticalBias = 0.5f;
            this.dimensionRatio = null;
            this.dimensionRatioValue = 0.0f;
            this.dimensionRatioSide = 1;
            this.horizontalWeight = -1.0f;
            this.verticalWeight = -1.0f;
            this.horizontalChainStyle = 0;
            this.verticalChainStyle = 0;
            this.matchConstraintDefaultWidth = 0;
            this.matchConstraintDefaultHeight = 0;
            this.matchConstraintMinWidth = 0;
            this.matchConstraintMinHeight = 0;
            this.matchConstraintMaxWidth = 0;
            this.matchConstraintMaxHeight = 0;
            this.matchConstraintPercentWidth = 1.0f;
            this.matchConstraintPercentHeight = 1.0f;
            this.editorAbsoluteX = -1;
            this.editorAbsoluteY = -1;
            this.orientation = -1;
            this.constrainedWidth = false;
            this.constrainedHeight = false;
            this.horizontalDimensionFixed = ConstraintLayout.USE_CONSTRAINTS_HELPER;
            this.verticalDimensionFixed = ConstraintLayout.USE_CONSTRAINTS_HELPER;
            this.needsBaseline = false;
            this.isGuideline = false;
            this.isHelper = false;
            this.isInPlaceholder = false;
            this.resolvedLeftToLeft = -1;
            this.resolvedLeftToRight = -1;
            this.resolvedRightToLeft = -1;
            this.resolvedRightToRight = -1;
            this.resolveGoneLeftMargin = -1;
            this.resolveGoneRightMargin = -1;
            this.resolvedHorizontalBias = 0.5f;
            this.widget = new ConstraintWidget();
            this.helped = false;
            this.guideBegin = source.guideBegin;
            this.guideEnd = source.guideEnd;
            this.guidePercent = source.guidePercent;
            this.leftToLeft = source.leftToLeft;
            this.leftToRight = source.leftToRight;
            this.rightToLeft = source.rightToLeft;
            this.rightToRight = source.rightToRight;
            this.topToTop = source.topToTop;
            this.topToBottom = source.topToBottom;
            this.bottomToTop = source.bottomToTop;
            this.bottomToBottom = source.bottomToBottom;
            this.baselineToBaseline = source.baselineToBaseline;
            this.circleConstraint = source.circleConstraint;
            this.circleRadius = source.circleRadius;
            this.circleAngle = source.circleAngle;
            this.startToEnd = source.startToEnd;
            this.startToStart = source.startToStart;
            this.endToStart = source.endToStart;
            this.endToEnd = source.endToEnd;
            this.goneLeftMargin = source.goneLeftMargin;
            this.goneTopMargin = source.goneTopMargin;
            this.goneRightMargin = source.goneRightMargin;
            this.goneBottomMargin = source.goneBottomMargin;
            this.goneStartMargin = source.goneStartMargin;
            this.goneEndMargin = source.goneEndMargin;
            this.horizontalBias = source.horizontalBias;
            this.verticalBias = source.verticalBias;
            this.dimensionRatio = source.dimensionRatio;
            this.dimensionRatioValue = source.dimensionRatioValue;
            this.dimensionRatioSide = source.dimensionRatioSide;
            this.horizontalWeight = source.horizontalWeight;
            this.verticalWeight = source.verticalWeight;
            this.horizontalChainStyle = source.horizontalChainStyle;
            this.verticalChainStyle = source.verticalChainStyle;
            this.constrainedWidth = source.constrainedWidth;
            this.constrainedHeight = source.constrainedHeight;
            this.matchConstraintDefaultWidth = source.matchConstraintDefaultWidth;
            this.matchConstraintDefaultHeight = source.matchConstraintDefaultHeight;
            this.matchConstraintMinWidth = source.matchConstraintMinWidth;
            this.matchConstraintMaxWidth = source.matchConstraintMaxWidth;
            this.matchConstraintMinHeight = source.matchConstraintMinHeight;
            this.matchConstraintMaxHeight = source.matchConstraintMaxHeight;
            this.matchConstraintPercentWidth = source.matchConstraintPercentWidth;
            this.matchConstraintPercentHeight = source.matchConstraintPercentHeight;
            this.editorAbsoluteX = source.editorAbsoluteX;
            this.editorAbsoluteY = source.editorAbsoluteY;
            this.orientation = source.orientation;
            this.horizontalDimensionFixed = source.horizontalDimensionFixed;
            this.verticalDimensionFixed = source.verticalDimensionFixed;
            this.needsBaseline = source.needsBaseline;
            this.isGuideline = source.isGuideline;
            this.resolvedLeftToLeft = source.resolvedLeftToLeft;
            this.resolvedLeftToRight = source.resolvedLeftToRight;
            this.resolvedRightToLeft = source.resolvedRightToLeft;
            this.resolvedRightToRight = source.resolvedRightToRight;
            this.resolveGoneLeftMargin = source.resolveGoneLeftMargin;
            this.resolveGoneRightMargin = source.resolveGoneRightMargin;
            this.resolvedHorizontalBias = source.resolvedHorizontalBias;
            this.widget = source.widget;
        }

        private static class Table {
            public static final int ANDROID_ORIENTATION = 1;
            public static final int LAYOUT_CONSTRAINED_HEIGHT = 28;
            public static final int LAYOUT_CONSTRAINED_WIDTH = 27;
            public static final int LAYOUT_CONSTRAINT_BASELINE_CREATOR = 43;
            public static final int LAYOUT_CONSTRAINT_BASELINE_TO_BASELINE_OF = 16;
            public static final int LAYOUT_CONSTRAINT_BOTTOM_CREATOR = 42;
            public static final int LAYOUT_CONSTRAINT_BOTTOM_TO_BOTTOM_OF = 15;
            public static final int LAYOUT_CONSTRAINT_BOTTOM_TO_TOP_OF = 14;
            public static final int LAYOUT_CONSTRAINT_CIRCLE = 2;
            public static final int LAYOUT_CONSTRAINT_CIRCLE_ANGLE = 4;
            public static final int LAYOUT_CONSTRAINT_CIRCLE_RADIUS = 3;
            public static final int LAYOUT_CONSTRAINT_DIMENSION_RATIO = 44;
            public static final int LAYOUT_CONSTRAINT_END_TO_END_OF = 20;
            public static final int LAYOUT_CONSTRAINT_END_TO_START_OF = 19;
            public static final int LAYOUT_CONSTRAINT_GUIDE_BEGIN = 5;
            public static final int LAYOUT_CONSTRAINT_GUIDE_END = 6;
            public static final int LAYOUT_CONSTRAINT_GUIDE_PERCENT = 7;
            public static final int LAYOUT_CONSTRAINT_HEIGHT_DEFAULT = 32;
            public static final int LAYOUT_CONSTRAINT_HEIGHT_MAX = 37;
            public static final int LAYOUT_CONSTRAINT_HEIGHT_MIN = 36;
            public static final int LAYOUT_CONSTRAINT_HEIGHT_PERCENT = 38;
            public static final int LAYOUT_CONSTRAINT_HORIZONTAL_BIAS = 29;
            public static final int LAYOUT_CONSTRAINT_HORIZONTAL_CHAINSTYLE = 47;
            public static final int LAYOUT_CONSTRAINT_HORIZONTAL_WEIGHT = 45;
            public static final int LAYOUT_CONSTRAINT_LEFT_CREATOR = 39;
            public static final int LAYOUT_CONSTRAINT_LEFT_TO_LEFT_OF = 8;
            public static final int LAYOUT_CONSTRAINT_LEFT_TO_RIGHT_OF = 9;
            public static final int LAYOUT_CONSTRAINT_RIGHT_CREATOR = 41;
            public static final int LAYOUT_CONSTRAINT_RIGHT_TO_LEFT_OF = 10;
            public static final int LAYOUT_CONSTRAINT_RIGHT_TO_RIGHT_OF = 11;
            public static final int LAYOUT_CONSTRAINT_START_TO_END_OF = 17;
            public static final int LAYOUT_CONSTRAINT_START_TO_START_OF = 18;
            public static final int LAYOUT_CONSTRAINT_TOP_CREATOR = 40;
            public static final int LAYOUT_CONSTRAINT_TOP_TO_BOTTOM_OF = 13;
            public static final int LAYOUT_CONSTRAINT_TOP_TO_TOP_OF = 12;
            public static final int LAYOUT_CONSTRAINT_VERTICAL_BIAS = 30;
            public static final int LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE = 48;
            public static final int LAYOUT_CONSTRAINT_VERTICAL_WEIGHT = 46;
            public static final int LAYOUT_CONSTRAINT_WIDTH_DEFAULT = 31;
            public static final int LAYOUT_CONSTRAINT_WIDTH_MAX = 34;
            public static final int LAYOUT_CONSTRAINT_WIDTH_MIN = 33;
            public static final int LAYOUT_CONSTRAINT_WIDTH_PERCENT = 35;
            public static final int LAYOUT_EDITOR_ABSOLUTEX = 49;
            public static final int LAYOUT_EDITOR_ABSOLUTEY = 50;
            public static final int LAYOUT_GONE_MARGIN_BOTTOM = 24;
            public static final int LAYOUT_GONE_MARGIN_END = 26;
            public static final int LAYOUT_GONE_MARGIN_LEFT = 21;
            public static final int LAYOUT_GONE_MARGIN_RIGHT = 23;
            public static final int LAYOUT_GONE_MARGIN_START = 25;
            public static final int LAYOUT_GONE_MARGIN_TOP = 22;
            public static final int UNUSED = 0;
            public static final SparseIntArray map = new SparseIntArray();

            private Table() {
            }

            static {
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintLeft_toLeftOf, 8);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintLeft_toRightOf, 9);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintRight_toLeftOf, 10);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintRight_toRightOf, 11);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintTop_toTopOf, 12);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintTop_toBottomOf, 13);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintBottom_toTopOf, 14);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintBottom_toBottomOf, 15);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintBaseline_toBaselineOf, 16);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintCircle, 2);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintCircleRadius, 3);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintCircleAngle, 4);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_editor_absoluteX, 49);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_editor_absoluteY, 50);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintGuide_begin, 5);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintGuide_end, 6);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintGuide_percent, 7);
                map.append(C0001R.styleable.ConstraintLayout_Layout_android_orientation, 1);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintStart_toEndOf, 17);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintStart_toStartOf, 18);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintEnd_toStartOf, 19);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintEnd_toEndOf, 20);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_goneMarginLeft, 21);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_goneMarginTop, 22);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_goneMarginRight, 23);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_goneMarginBottom, 24);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_goneMarginStart, 25);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_goneMarginEnd, 26);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintHorizontal_bias, 29);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintVertical_bias, 30);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintDimensionRatio, 44);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintHorizontal_weight, 45);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintVertical_weight, 46);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintHorizontal_chainStyle, 47);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintVertical_chainStyle, 48);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constrainedWidth, 27);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constrainedHeight, 28);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintWidth_default, 31);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintHeight_default, 32);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintWidth_min, 33);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintWidth_max, 34);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintWidth_percent, 35);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintHeight_min, 36);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintHeight_max, 37);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintHeight_percent, 38);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintLeft_creator, 39);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintTop_creator, 40);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintRight_creator, 41);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintBottom_creator, 42);
                map.append(C0001R.styleable.ConstraintLayout_Layout_layout_constraintBaseline_creator, 43);
            }
        }

        /* JADX INFO: Can't fix incorrect switch cases order, some code will duplicate */
        /* JADX DEBUG: Failed to find minimal casts for resolve overloaded methods, cast all args instead
         method: ClspMth{java.lang.Math.max(float, float):float}
         arg types: [int, float]
         candidates:
          ClspMth{java.lang.Math.max(double, double):double}
          ClspMth{java.lang.Math.max(int, int):int}
          ClspMth{java.lang.Math.max(long, long):long}
          ClspMth{java.lang.Math.max(float, float):float} */
        public LayoutParams(Context c, AttributeSet attrs) {
            super(c, attrs);
            float f;
            int i;
            int i2;
            int i3;
            int i4;
            int i5;
            int commaIndex;
            int i6 = -1;
            this.guideBegin = -1;
            this.guideEnd = -1;
            this.guidePercent = -1.0f;
            this.leftToLeft = -1;
            this.leftToRight = -1;
            this.rightToLeft = -1;
            this.rightToRight = -1;
            this.topToTop = -1;
            this.topToBottom = -1;
            this.bottomToTop = -1;
            this.bottomToBottom = -1;
            this.baselineToBaseline = -1;
            this.circleConstraint = -1;
            int i7 = 0;
            this.circleRadius = 0;
            float f2 = 0.0f;
            this.circleAngle = 0.0f;
            this.startToEnd = -1;
            this.startToStart = -1;
            this.endToStart = -1;
            this.endToEnd = -1;
            this.goneLeftMargin = -1;
            this.goneTopMargin = -1;
            this.goneRightMargin = -1;
            this.goneBottomMargin = -1;
            this.goneStartMargin = -1;
            this.goneEndMargin = -1;
            this.horizontalBias = 0.5f;
            this.verticalBias = 0.5f;
            this.dimensionRatio = null;
            this.dimensionRatioValue = 0.0f;
            int i8 = 1;
            this.dimensionRatioSide = 1;
            this.horizontalWeight = -1.0f;
            this.verticalWeight = -1.0f;
            this.horizontalChainStyle = 0;
            this.verticalChainStyle = 0;
            this.matchConstraintDefaultWidth = 0;
            this.matchConstraintDefaultHeight = 0;
            this.matchConstraintMinWidth = 0;
            this.matchConstraintMinHeight = 0;
            this.matchConstraintMaxWidth = 0;
            this.matchConstraintMaxHeight = 0;
            this.matchConstraintPercentWidth = 1.0f;
            this.matchConstraintPercentHeight = 1.0f;
            this.editorAbsoluteX = -1;
            this.editorAbsoluteY = -1;
            this.orientation = -1;
            this.constrainedWidth = false;
            this.constrainedHeight = false;
            this.horizontalDimensionFixed = ConstraintLayout.USE_CONSTRAINTS_HELPER;
            this.verticalDimensionFixed = ConstraintLayout.USE_CONSTRAINTS_HELPER;
            this.needsBaseline = false;
            this.isGuideline = false;
            this.isHelper = false;
            this.isInPlaceholder = false;
            this.resolvedLeftToLeft = -1;
            this.resolvedLeftToRight = -1;
            this.resolvedRightToLeft = -1;
            this.resolvedRightToRight = -1;
            this.resolveGoneLeftMargin = -1;
            this.resolveGoneRightMargin = -1;
            this.resolvedHorizontalBias = 0.5f;
            this.widget = new ConstraintWidget();
            this.helped = false;
            TypedArray a = c.obtainStyledAttributes(attrs, C0001R.styleable.ConstraintLayout_Layout);
            int N = a.getIndexCount();
            int i9 = 0;
            while (i9 < N) {
                int attr = a.getIndex(i9);
                switch (Table.map.get(attr)) {
                    case 0:
                        f = f2;
                        i2 = i8;
                        i = i6;
                        i3 = i7;
                        break;
                    case 1:
                        f = f2;
                        i2 = i8;
                        i = i6;
                        i3 = i7;
                        this.orientation = a.getInt(attr, this.orientation);
                        break;
                    case 2:
                        i3 = i7;
                        f = f2;
                        i2 = i8;
                        this.circleConstraint = a.getResourceId(attr, this.circleConstraint);
                        i = -1;
                        if (this.circleConstraint != -1) {
                            break;
                        } else {
                            this.circleConstraint = a.getInt(attr, -1);
                            break;
                        }
                    case 3:
                        i4 = i7;
                        f = f2;
                        i5 = i8;
                        this.circleRadius = a.getDimensionPixelSize(attr, this.circleRadius);
                        i = -1;
                        break;
                    case 4:
                        i4 = i7;
                        i5 = i8;
                        this.circleAngle = a.getFloat(attr, this.circleAngle) % 360.0f;
                        f = 0.0f;
                        if (this.circleAngle < 0.0f) {
                            this.circleAngle = (360.0f - this.circleAngle) % 360.0f;
                        }
                        i = -1;
                        break;
                    case 5:
                        i3 = i7;
                        i2 = i8;
                        this.guideBegin = a.getDimensionPixelOffset(attr, this.guideBegin);
                        i = -1;
                        f = 0.0f;
                        break;
                    case 6:
                        i3 = i7;
                        i2 = i8;
                        this.guideEnd = a.getDimensionPixelOffset(attr, this.guideEnd);
                        i = -1;
                        f = 0.0f;
                        break;
                    case 7:
                        i3 = i7;
                        i2 = i8;
                        this.guidePercent = a.getFloat(attr, this.guidePercent);
                        i = -1;
                        f = 0.0f;
                        break;
                    case 8:
                        i2 = i8;
                        i = i6;
                        i3 = i7;
                        this.leftToLeft = a.getResourceId(attr, this.leftToLeft);
                        if (this.leftToLeft == i) {
                            this.leftToLeft = a.getInt(attr, i);
                            i = -1;
                        }
                        f = 0.0f;
                        break;
                    case 9:
                        i2 = i8;
                        i = i6;
                        i3 = i7;
                        this.leftToRight = a.getResourceId(attr, this.leftToRight);
                        if (this.leftToRight == i) {
                            this.leftToRight = a.getInt(attr, i);
                        }
                        f = 0.0f;
                        break;
                    case 10:
                        i2 = i8;
                        i = i6;
                        i3 = i7;
                        this.rightToLeft = a.getResourceId(attr, this.rightToLeft);
                        if (this.rightToLeft == i) {
                            this.rightToLeft = a.getInt(attr, i);
                        }
                        f = 0.0f;
                        break;
                    case 11:
                        i2 = i8;
                        i = i6;
                        i3 = i7;
                        this.rightToRight = a.getResourceId(attr, this.rightToRight);
                        if (this.rightToRight == i) {
                            this.rightToRight = a.getInt(attr, i);
                        }
                        f = 0.0f;
                        break;
                    case 12:
                        i2 = i8;
                        i = i6;
                        i3 = i7;
                        this.topToTop = a.getResourceId(attr, this.topToTop);
                        if (this.topToTop == i) {
                            this.topToTop = a.getInt(attr, i);
                        }
                        f = 0.0f;
                        break;
                    case 13:
                        i2 = i8;
                        i = i6;
                        i3 = i7;
                        this.topToBottom = a.getResourceId(attr, this.topToBottom);
                        if (this.topToBottom == i) {
                            this.topToBottom = a.getInt(attr, i);
                        }
                        f = 0.0f;
                        break;
                    case 14:
                        i2 = i8;
                        i = i6;
                        i3 = i7;
                        this.bottomToTop = a.getResourceId(attr, this.bottomToTop);
                        if (this.bottomToTop == i) {
                            this.bottomToTop = a.getInt(attr, i);
                        }
                        f = 0.0f;
                        break;
                    case 15:
                        i2 = i8;
                        i = i6;
                        i3 = i7;
                        this.bottomToBottom = a.getResourceId(attr, this.bottomToBottom);
                        if (this.bottomToBottom == i) {
                            this.bottomToBottom = a.getInt(attr, i);
                        }
                        f = 0.0f;
                        break;
                    case 16:
                        i2 = i8;
                        i = i6;
                        i3 = i7;
                        this.baselineToBaseline = a.getResourceId(attr, this.baselineToBaseline);
                        if (this.baselineToBaseline == i) {
                            this.baselineToBaseline = a.getInt(attr, i);
                        }
                        f = 0.0f;
                        break;
                    case 17:
                        i2 = i8;
                        i = i6;
                        i3 = i7;
                        this.startToEnd = a.getResourceId(attr, this.startToEnd);
                        if (this.startToEnd == i) {
                            this.startToEnd = a.getInt(attr, i);
                        }
                        f = 0.0f;
                        break;
                    case 18:
                        i2 = i8;
                        i = i6;
                        i3 = i7;
                        this.startToStart = a.getResourceId(attr, this.startToStart);
                        if (this.startToStart == i) {
                            this.startToStart = a.getInt(attr, i);
                        }
                        f = 0.0f;
                        break;
                    case 19:
                        i2 = i8;
                        i = i6;
                        i3 = i7;
                        this.endToStart = a.getResourceId(attr, this.endToStart);
                        if (this.endToStart == i) {
                            this.endToStart = a.getInt(attr, i);
                        }
                        f = 0.0f;
                        break;
                    case 20:
                        i3 = i7;
                        i2 = i8;
                        this.endToEnd = a.getResourceId(attr, this.endToEnd);
                        i = -1;
                        if (this.endToEnd == -1) {
                            this.endToEnd = a.getInt(attr, -1);
                        }
                        f = 0.0f;
                        break;
                    case 21:
                        i3 = i7;
                        i2 = i8;
                        this.goneLeftMargin = a.getDimensionPixelSize(attr, this.goneLeftMargin);
                        i = -1;
                        f = 0.0f;
                        break;
                    case 22:
                        i3 = i7;
                        i2 = i8;
                        this.goneTopMargin = a.getDimensionPixelSize(attr, this.goneTopMargin);
                        i = -1;
                        f = 0.0f;
                        break;
                    case 23:
                        i3 = i7;
                        i2 = i8;
                        this.goneRightMargin = a.getDimensionPixelSize(attr, this.goneRightMargin);
                        i = -1;
                        f = 0.0f;
                        break;
                    case 24:
                        i3 = i7;
                        i2 = i8;
                        this.goneBottomMargin = a.getDimensionPixelSize(attr, this.goneBottomMargin);
                        i = -1;
                        f = 0.0f;
                        break;
                    case 25:
                        i3 = i7;
                        i2 = i8;
                        this.goneStartMargin = a.getDimensionPixelSize(attr, this.goneStartMargin);
                        i = -1;
                        f = 0.0f;
                        break;
                    case 26:
                        i3 = i7;
                        i2 = i8;
                        this.goneEndMargin = a.getDimensionPixelSize(attr, this.goneEndMargin);
                        i = -1;
                        f = 0.0f;
                        break;
                    case 27:
                        i3 = i7;
                        i2 = i8;
                        this.constrainedWidth = a.getBoolean(attr, this.constrainedWidth);
                        i = -1;
                        f = 0.0f;
                        break;
                    case 28:
                        i3 = i7;
                        i2 = i8;
                        this.constrainedHeight = a.getBoolean(attr, this.constrainedHeight);
                        i = -1;
                        f = 0.0f;
                        break;
                    case 29:
                        i3 = i7;
                        i2 = i8;
                        this.horizontalBias = a.getFloat(attr, this.horizontalBias);
                        i = -1;
                        f = 0.0f;
                        break;
                    case 30:
                        i3 = i7;
                        i2 = i8;
                        this.verticalBias = a.getFloat(attr, this.verticalBias);
                        i = -1;
                        f = 0.0f;
                        break;
                    case 31:
                        i3 = 0;
                        this.matchConstraintDefaultWidth = a.getInt(attr, 0);
                        i2 = 1;
                        if (this.matchConstraintDefaultWidth == 1) {
                            Log.e(ConstraintLayout.TAG, "layout_constraintWidth_default=\"wrap\" is deprecated.\nUse layout_width=\"WRAP_CONTENT\" and layout_constrainedWidth=\"true\" instead.");
                        }
                        i = -1;
                        f = 0.0f;
                        break;
                    case 32:
                        this.matchConstraintDefaultHeight = a.getInt(attr, 0);
                        if (this.matchConstraintDefaultHeight == 1) {
                            Log.e(ConstraintLayout.TAG, "layout_constraintHeight_default=\"wrap\" is deprecated.\nUse layout_height=\"WRAP_CONTENT\" and layout_constrainedHeight=\"true\" instead.");
                            i3 = 0;
                            i2 = 1;
                            i = -1;
                            f = 0.0f;
                            break;
                        } else {
                            i2 = 1;
                            i3 = 0;
                            i = -1;
                            f = 0.0f;
                        }
                    case 33:
                        try {
                            this.matchConstraintMinWidth = a.getDimensionPixelSize(attr, this.matchConstraintMinWidth);
                        } catch (Exception e) {
                            if (a.getInt(attr, this.matchConstraintMinWidth) == -2) {
                                this.matchConstraintMinWidth = -2;
                            }
                        }
                        i3 = 0;
                        i2 = 1;
                        i = -1;
                        f = 0.0f;
                        break;
                    case 34:
                        try {
                            this.matchConstraintMaxWidth = a.getDimensionPixelSize(attr, this.matchConstraintMaxWidth);
                        } catch (Exception e2) {
                            if (a.getInt(attr, this.matchConstraintMaxWidth) == -2) {
                                this.matchConstraintMaxWidth = -2;
                            }
                        }
                        i3 = 0;
                        i2 = 1;
                        i = -1;
                        f = 0.0f;
                        break;
                    case 35:
                        this.matchConstraintPercentWidth = Math.max(0.0f, a.getFloat(attr, this.matchConstraintPercentWidth));
                        i3 = 0;
                        i2 = 1;
                        i = -1;
                        f = 0.0f;
                        break;
                    case 36:
                        try {
                            this.matchConstraintMinHeight = a.getDimensionPixelSize(attr, this.matchConstraintMinHeight);
                        } catch (Exception e3) {
                            if (a.getInt(attr, this.matchConstraintMinHeight) == -2) {
                                this.matchConstraintMinHeight = -2;
                            }
                        }
                        i3 = 0;
                        i2 = 1;
                        i = -1;
                        f = 0.0f;
                        break;
                    case 37:
                        try {
                            this.matchConstraintMaxHeight = a.getDimensionPixelSize(attr, this.matchConstraintMaxHeight);
                        } catch (Exception e4) {
                            if (a.getInt(attr, this.matchConstraintMaxHeight) == -2) {
                                this.matchConstraintMaxHeight = -2;
                            }
                        }
                        i3 = 0;
                        i2 = 1;
                        i = -1;
                        f = 0.0f;
                        break;
                    case 38:
                        this.matchConstraintPercentHeight = Math.max(0.0f, a.getFloat(attr, this.matchConstraintPercentHeight));
                        i3 = 0;
                        i2 = 1;
                        i = -1;
                        f = 0.0f;
                        break;
                    case 39:
                    case 40:
                    case 41:
                    case 42:
                        i3 = 0;
                        i2 = 1;
                        i = -1;
                        f = 0.0f;
                        break;
                    case 43:
                    default:
                        f = f2;
                        i2 = i8;
                        i = i6;
                        i3 = i7;
                        break;
                    case 44:
                        this.dimensionRatio = a.getString(attr);
                        this.dimensionRatioValue = Float.NaN;
                        this.dimensionRatioSide = i6;
                        if (this.dimensionRatio != null) {
                            int len = this.dimensionRatio.length();
                            int commaIndex2 = this.dimensionRatio.indexOf(44);
                            if (commaIndex2 <= 0 || commaIndex2 >= len - 1) {
                                commaIndex = 0;
                            } else {
                                String dimension = this.dimensionRatio.substring(i7, commaIndex2);
                                if (dimension.equalsIgnoreCase("W")) {
                                    this.dimensionRatioSide = i7;
                                } else if (dimension.equalsIgnoreCase("H")) {
                                    this.dimensionRatioSide = i8;
                                }
                                commaIndex = commaIndex2 + 1;
                            }
                            int colonIndex = this.dimensionRatio.indexOf(58);
                            if (colonIndex < 0 || colonIndex >= len - 1) {
                                String r = this.dimensionRatio.substring(commaIndex);
                                if (r.length() > 0) {
                                    try {
                                        this.dimensionRatioValue = Float.parseFloat(r);
                                    } catch (NumberFormatException e5) {
                                    }
                                }
                                i3 = 0;
                                i2 = 1;
                                i = -1;
                                f = 0.0f;
                                break;
                            } else {
                                String nominator = this.dimensionRatio.substring(commaIndex, colonIndex);
                                String denominator = this.dimensionRatio.substring(colonIndex + 1);
                                if (nominator.length() <= 0 || denominator.length() <= 0) {
                                    i3 = 0;
                                    i2 = 1;
                                    i = -1;
                                    f = 0.0f;
                                } else {
                                    try {
                                        float nominatorValue = Float.parseFloat(nominator);
                                        float denominatorValue = Float.parseFloat(denominator);
                                        if (nominatorValue <= f2 || denominatorValue <= f2) {
                                            i3 = 0;
                                            i2 = 1;
                                            i = -1;
                                            f = 0.0f;
                                        } else {
                                            if (this.dimensionRatioSide == 1) {
                                                try {
                                                    this.dimensionRatioValue = Math.abs(denominatorValue / nominatorValue);
                                                } catch (NumberFormatException e6) {
                                                }
                                            } else {
                                                this.dimensionRatioValue = Math.abs(nominatorValue / denominatorValue);
                                            }
                                            i3 = 0;
                                            i2 = 1;
                                            i = -1;
                                            f = 0.0f;
                                        }
                                    } catch (NumberFormatException e7) {
                                    }
                                }
                            }
                        }
                        f = f2;
                        i2 = i8;
                        i = i6;
                        i3 = i7;
                        break;
                    case 45:
                        this.horizontalWeight = a.getFloat(attr, this.horizontalWeight);
                        f = f2;
                        i2 = i8;
                        i = i6;
                        i3 = i7;
                        break;
                    case 46:
                        this.verticalWeight = a.getFloat(attr, this.verticalWeight);
                        f = f2;
                        i2 = i8;
                        i = i6;
                        i3 = i7;
                        break;
                    case 47:
                        this.horizontalChainStyle = a.getInt(attr, i7);
                        f = f2;
                        i2 = i8;
                        i = i6;
                        i3 = i7;
                        break;
                    case 48:
                        this.verticalChainStyle = a.getInt(attr, i7);
                        f = f2;
                        i2 = i8;
                        i = i6;
                        i3 = i7;
                        break;
                    case 49:
                        this.editorAbsoluteX = a.getDimensionPixelOffset(attr, this.editorAbsoluteX);
                        f = f2;
                        i2 = i8;
                        i = i6;
                        i3 = i7;
                        break;
                    case 50:
                        this.editorAbsoluteY = a.getDimensionPixelOffset(attr, this.editorAbsoluteY);
                        f = f2;
                        i2 = i8;
                        i = i6;
                        i3 = i7;
                        break;
                }
                i9++;
                i7 = i3;
                i6 = i;
                i8 = i2;
                f2 = f;
            }
            a.recycle();
            validate();
        }

        public void validate() {
            this.isGuideline = false;
            this.horizontalDimensionFixed = ConstraintLayout.USE_CONSTRAINTS_HELPER;
            this.verticalDimensionFixed = ConstraintLayout.USE_CONSTRAINTS_HELPER;
            if (this.width == -2 && this.constrainedWidth) {
                this.horizontalDimensionFixed = false;
                this.matchConstraintDefaultWidth = 1;
            }
            if (this.height == -2 && this.constrainedHeight) {
                this.verticalDimensionFixed = false;
                this.matchConstraintDefaultHeight = 1;
            }
            if (this.width == 0 || this.width == -1) {
                this.horizontalDimensionFixed = false;
                if (this.width == 0 && this.matchConstraintDefaultWidth == 1) {
                    this.width = -2;
                    this.constrainedWidth = ConstraintLayout.USE_CONSTRAINTS_HELPER;
                }
            }
            if (this.height == 0 || this.height == -1) {
                this.verticalDimensionFixed = false;
                if (this.height == 0 && this.matchConstraintDefaultHeight == 1) {
                    this.height = -2;
                    this.constrainedHeight = ConstraintLayout.USE_CONSTRAINTS_HELPER;
                }
            }
            if (this.guidePercent != -1.0f || this.guideBegin != -1 || this.guideEnd != -1) {
                this.isGuideline = ConstraintLayout.USE_CONSTRAINTS_HELPER;
                this.horizontalDimensionFixed = ConstraintLayout.USE_CONSTRAINTS_HELPER;
                this.verticalDimensionFixed = ConstraintLayout.USE_CONSTRAINTS_HELPER;
                if (!(this.widget instanceof Guideline)) {
                    this.widget = new Guideline();
                }
                ((Guideline) this.widget).setOrientation(this.orientation);
            }
        }

        public LayoutParams(int width, int height) {
            super(width, height);
            this.guideBegin = -1;
            this.guideEnd = -1;
            this.guidePercent = -1.0f;
            this.leftToLeft = -1;
            this.leftToRight = -1;
            this.rightToLeft = -1;
            this.rightToRight = -1;
            this.topToTop = -1;
            this.topToBottom = -1;
            this.bottomToTop = -1;
            this.bottomToBottom = -1;
            this.baselineToBaseline = -1;
            this.circleConstraint = -1;
            this.circleRadius = 0;
            this.circleAngle = 0.0f;
            this.startToEnd = -1;
            this.startToStart = -1;
            this.endToStart = -1;
            this.endToEnd = -1;
            this.goneLeftMargin = -1;
            this.goneTopMargin = -1;
            this.goneRightMargin = -1;
            this.goneBottomMargin = -1;
            this.goneStartMargin = -1;
            this.goneEndMargin = -1;
            this.horizontalBias = 0.5f;
            this.verticalBias = 0.5f;
            this.dimensionRatio = null;
            this.dimensionRatioValue = 0.0f;
            this.dimensionRatioSide = 1;
            this.horizontalWeight = -1.0f;
            this.verticalWeight = -1.0f;
            this.horizontalChainStyle = 0;
            this.verticalChainStyle = 0;
            this.matchConstraintDefaultWidth = 0;
            this.matchConstraintDefaultHeight = 0;
            this.matchConstraintMinWidth = 0;
            this.matchConstraintMinHeight = 0;
            this.matchConstraintMaxWidth = 0;
            this.matchConstraintMaxHeight = 0;
            this.matchConstraintPercentWidth = 1.0f;
            this.matchConstraintPercentHeight = 1.0f;
            this.editorAbsoluteX = -1;
            this.editorAbsoluteY = -1;
            this.orientation = -1;
            this.constrainedWidth = false;
            this.constrainedHeight = false;
            this.horizontalDimensionFixed = ConstraintLayout.USE_CONSTRAINTS_HELPER;
            this.verticalDimensionFixed = ConstraintLayout.USE_CONSTRAINTS_HELPER;
            this.needsBaseline = false;
            this.isGuideline = false;
            this.isHelper = false;
            this.isInPlaceholder = false;
            this.resolvedLeftToLeft = -1;
            this.resolvedLeftToRight = -1;
            this.resolvedRightToLeft = -1;
            this.resolvedRightToRight = -1;
            this.resolveGoneLeftMargin = -1;
            this.resolveGoneRightMargin = -1;
            this.resolvedHorizontalBias = 0.5f;
            this.widget = new ConstraintWidget();
            this.helped = false;
        }

        public LayoutParams(ViewGroup.LayoutParams source) {
            super(source);
            this.guideBegin = -1;
            this.guideEnd = -1;
            this.guidePercent = -1.0f;
            this.leftToLeft = -1;
            this.leftToRight = -1;
            this.rightToLeft = -1;
            this.rightToRight = -1;
            this.topToTop = -1;
            this.topToBottom = -1;
            this.bottomToTop = -1;
            this.bottomToBottom = -1;
            this.baselineToBaseline = -1;
            this.circleConstraint = -1;
            this.circleRadius = 0;
            this.circleAngle = 0.0f;
            this.startToEnd = -1;
            this.startToStart = -1;
            this.endToStart = -1;
            this.endToEnd = -1;
            this.goneLeftMargin = -1;
            this.goneTopMargin = -1;
            this.goneRightMargin = -1;
            this.goneBottomMargin = -1;
            this.goneStartMargin = -1;
            this.goneEndMargin = -1;
            this.horizontalBias = 0.5f;
            this.verticalBias = 0.5f;
            this.dimensionRatio = null;
            this.dimensionRatioValue = 0.0f;
            this.dimensionRatioSide = 1;
            this.horizontalWeight = -1.0f;
            this.verticalWeight = -1.0f;
            this.horizontalChainStyle = 0;
            this.verticalChainStyle = 0;
            this.matchConstraintDefaultWidth = 0;
            this.matchConstraintDefaultHeight = 0;
            this.matchConstraintMinWidth = 0;
            this.matchConstraintMinHeight = 0;
            this.matchConstraintMaxWidth = 0;
            this.matchConstraintMaxHeight = 0;
            this.matchConstraintPercentWidth = 1.0f;
            this.matchConstraintPercentHeight = 1.0f;
            this.editorAbsoluteX = -1;
            this.editorAbsoluteY = -1;
            this.orientation = -1;
            this.constrainedWidth = false;
            this.constrainedHeight = false;
            this.horizontalDimensionFixed = ConstraintLayout.USE_CONSTRAINTS_HELPER;
            this.verticalDimensionFixed = ConstraintLayout.USE_CONSTRAINTS_HELPER;
            this.needsBaseline = false;
            this.isGuideline = false;
            this.isHelper = false;
            this.isInPlaceholder = false;
            this.resolvedLeftToLeft = -1;
            this.resolvedLeftToRight = -1;
            this.resolvedRightToLeft = -1;
            this.resolvedRightToRight = -1;
            this.resolveGoneLeftMargin = -1;
            this.resolveGoneRightMargin = -1;
            this.resolvedHorizontalBias = 0.5f;
            this.widget = new ConstraintWidget();
            this.helped = false;
        }

        @TargetApi(17)
        public void resolveLayoutDirection(int layoutDirection) {
            int preLeftMargin = this.leftMargin;
            int preRightMargin = this.rightMargin;
            super.resolveLayoutDirection(layoutDirection);
            this.resolvedRightToLeft = -1;
            this.resolvedRightToRight = -1;
            this.resolvedLeftToLeft = -1;
            this.resolvedLeftToRight = -1;
            this.resolveGoneLeftMargin = -1;
            this.resolveGoneRightMargin = -1;
            this.resolveGoneLeftMargin = this.goneLeftMargin;
            this.resolveGoneRightMargin = this.goneRightMargin;
            this.resolvedHorizontalBias = this.horizontalBias;
            this.resolvedGuideBegin = this.guideBegin;
            this.resolvedGuideEnd = this.guideEnd;
            this.resolvedGuidePercent = this.guidePercent;
            if (1 == getLayoutDirection()) {
                boolean startEndDefined = false;
                if (this.startToEnd != -1) {
                    this.resolvedRightToLeft = this.startToEnd;
                    startEndDefined = ConstraintLayout.USE_CONSTRAINTS_HELPER;
                } else if (this.startToStart != -1) {
                    this.resolvedRightToRight = this.startToStart;
                    startEndDefined = ConstraintLayout.USE_CONSTRAINTS_HELPER;
                }
                if (this.endToStart != -1) {
                    this.resolvedLeftToRight = this.endToStart;
                    startEndDefined = ConstraintLayout.USE_CONSTRAINTS_HELPER;
                }
                if (this.endToEnd != -1) {
                    this.resolvedLeftToLeft = this.endToEnd;
                    startEndDefined = ConstraintLayout.USE_CONSTRAINTS_HELPER;
                }
                if (this.goneStartMargin != -1) {
                    this.resolveGoneRightMargin = this.goneStartMargin;
                }
                if (this.goneEndMargin != -1) {
                    this.resolveGoneLeftMargin = this.goneEndMargin;
                }
                if (startEndDefined) {
                    this.resolvedHorizontalBias = 1.0f - this.horizontalBias;
                }
                if (this.isGuideline && this.orientation == 1) {
                    if (this.guidePercent != -1.0f) {
                        this.resolvedGuidePercent = 1.0f - this.guidePercent;
                        this.resolvedGuideBegin = -1;
                        this.resolvedGuideEnd = -1;
                    } else if (this.guideBegin != -1) {
                        this.resolvedGuideEnd = this.guideBegin;
                        this.resolvedGuideBegin = -1;
                        this.resolvedGuidePercent = -1.0f;
                    } else if (this.guideEnd != -1) {
                        this.resolvedGuideBegin = this.guideEnd;
                        this.resolvedGuideEnd = -1;
                        this.resolvedGuidePercent = -1.0f;
                    }
                }
            } else {
                if (this.startToEnd != -1) {
                    this.resolvedLeftToRight = this.startToEnd;
                }
                if (this.startToStart != -1) {
                    this.resolvedLeftToLeft = this.startToStart;
                }
                if (this.endToStart != -1) {
                    this.resolvedRightToLeft = this.endToStart;
                }
                if (this.endToEnd != -1) {
                    this.resolvedRightToRight = this.endToEnd;
                }
                if (this.goneStartMargin != -1) {
                    this.resolveGoneLeftMargin = this.goneStartMargin;
                }
                if (this.goneEndMargin != -1) {
                    this.resolveGoneRightMargin = this.goneEndMargin;
                }
            }
            if (this.endToStart == -1 && this.endToEnd == -1 && this.startToStart == -1 && this.startToEnd == -1) {
                if (this.rightToLeft != -1) {
                    this.resolvedRightToLeft = this.rightToLeft;
                    if (this.rightMargin <= 0 && preRightMargin > 0) {
                        this.rightMargin = preRightMargin;
                    }
                } else if (this.rightToRight != -1) {
                    this.resolvedRightToRight = this.rightToRight;
                    if (this.rightMargin <= 0 && preRightMargin > 0) {
                        this.rightMargin = preRightMargin;
                    }
                }
                if (this.leftToLeft != -1) {
                    this.resolvedLeftToLeft = this.leftToLeft;
                    if (this.leftMargin <= 0 && preLeftMargin > 0) {
                        this.leftMargin = preLeftMargin;
                    }
                } else if (this.leftToRight != -1) {
                    this.resolvedLeftToRight = this.leftToRight;
                    if (this.leftMargin <= 0 && preLeftMargin > 0) {
                        this.leftMargin = preLeftMargin;
                    }
                }
            }
        }
    }

    public void requestLayout() {
        super.requestLayout();
        this.mDirtyHierarchy = USE_CONSTRAINTS_HELPER;
        this.mLastMeasureWidth = -1;
        this.mLastMeasureHeight = -1;
        this.mLastMeasureWidthSize = -1;
        this.mLastMeasureHeightSize = -1;
        this.mLastMeasureWidthMode = 0;
        this.mLastMeasureHeightMode = 0;
    }

    public boolean shouldDelayChildPressedState() {
        return false;
    }
}
