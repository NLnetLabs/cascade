//! Reviewing instances of zones.
//!
//! Zone review is a central feature of Cascade.

//----------- PendingReviewState -----------------------------------------------

/// The review state of a pending (signed or unsigned) instance of a zone.
#[derive(Debug)]
pub struct PendingReviewState {
    /// Rejections of the zone.
    ///
    /// The instance could have been rejected multiple times before being
    /// approved; information about those rejections is catalogued here.
    pub rejections: Vec<()>,
}

//----------- ApprovedReviewState ----------------------------------------------

/// The review state of an old (signed or unsigned) instance of a zone.
#[derive(Debug)]
pub struct ApprovedReviewState {
    /// Rejections of the zone.
    ///
    /// The instance could have been rejected multiple times before being
    /// approved; information about those rejections is catalogued here.
    pub rejections: Vec<()>,

    /// The approval of the zone.
    ///
    /// The instance can only be approved once; once it has been approved, it
    /// may progress into future stages (e.g. signing and publishing), and can
    /// no longer be reviewed.  Information about the approval is stored here.
    pub approval: (),
}
